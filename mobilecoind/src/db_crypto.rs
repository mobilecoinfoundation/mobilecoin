// Copyright (c) 2018-2026 The MobileCoin Foundation

//! Versioned database encryption. Legacy encryption is supported only for reads
//! during migration.

use aes_gcm::{
    aead::{array::typenum::Unsigned, Aead, Payload},
    AeadCore, Aes256Gcm, Error as AeadError, KeyInit, KeySizeUser,
};
use argon2::{Algorithm, Argon2, Params, Version};
use displaydoc::Display;
use lmdb::{
    Database, DatabaseFlags, Environment, Error as LmdbError, RwTransaction, Transaction,
    WriteFlags,
};
use mc_crypto_hashes::{Blake2b512, Digest};
use rand::{rngs::SysRng, TryRng};

/// Clients supply a 32-byte password hash, rather than a raw password.
pub const PASSWORD_LEN: usize = 32;
/// Domain separator used by the old format, retained for migration reads.
const LEGACY_DOMAIN: &[u8] = b"mc_mobilecoind";
/// Domain separator for deriving v1 keys from the salt and password hash.
const KEY_DOMAIN: &[u8] = b"mc_mobilecoind_db_v1";
/// Authenticated context for v1 records: the key domain followed by the version
/// byte.
const RECORD_AAD: &[u8] = b"mc_mobilecoind_db_v1\x01";
/// First byte of the encrypted record: version || nonce || ciphertext and tag.
const RECORD_VERSION: u8 = 1;
/// AES-256-GCM encryption key length (256 bits).
const KEY_LEN: usize = <Aes256Gcm as KeySizeUser>::KeySize::USIZE;
/// AES-256-GCM nonce length (96 bits).
const NONCE_LEN: usize = <Aes256Gcm as AeadCore>::NonceSize::USIZE;
/// AES-256-GCM authentication tag length (128 bits).
const TAG_LEN: usize = <Aes256Gcm as AeadCore>::TagSize::USIZE;
/// Random salt length (256 bits); re-encrypting the database creates a new
/// salt.
const SALT_LEN: usize = 32;
/// LMDB database containing encryption metadata.
const CRYPTO_DB_NAME: &str = "db_crypto";
/// Metadata key for the password-check marker; its presence enables encryption.
const ENCRYPTION_STATE_KEY: &[u8] = b"db_encrypted";
/// Known marker plaintext used to verify the supplied password hash.
const ENCRYPTION_STATE_VAL: &[u8] = b"true";
/// Metadata key for the salt used to derive the current v1 encryption key.
const KEY_SALT_KEY: &[u8] = b"key_salt";

/// Encryption scheme used to derive keys and decode encrypted database records.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum CryptoFormat {
    /// AES-256-GCM with a key and fixed nonce derived from the password hash.
    /// Supported only for reading records during migration.
    Legacy,
    /// AES-256-GCM with a salted key and a fresh random nonce for each write.
    /// Records contain a version byte, nonce, ciphertext, and authentication
    /// tag.
    V1,
}

/// Possible db crypto error types.
#[derive(Debug, Display)]
pub enum DbCryptoError {
    /// Invalid password length
    InvalidPasswordLength,
    /// Invalid password
    InvalidPassword,
    /// Password needed
    PasswordNeeded,
    /// Invalid encrypted database format
    InvalidFormat,
    /// Legacy database requires migration before writing
    MigrationRequired,
    /// AEAD: {0}
    Aead(AeadError),
    /// Argon2: {0}
    Argon2(argon2::Error),
    /// LMDB: {0}
    Lmdb(LmdbError),
}

impl From<AeadError> for DbCryptoError {
    fn from(src: AeadError) -> Self {
        Self::Aead(src)
    }
}

impl From<LmdbError> for DbCryptoError {
    fn from(src: LmdbError) -> Self {
        Self::Lmdb(src)
    }
}

/// A candidate context is independent of the live provider until commit. Do not
/// derive Debug: this contains key material.
#[derive(Clone)]
pub(crate) enum CryptoContext {
    Plaintext,
    Legacy {
        key: [u8; KEY_LEN],
        nonce: [u8; NONCE_LEN],
    },
    V1 {
        key: [u8; KEY_LEN],
        salt: [u8; SALT_LEN],
    },
}

impl CryptoContext {
    /// Create a new encryption generation, even when reusing a password.
    pub(crate) fn new(password: &[u8]) -> Result<Self, DbCryptoError> {
        if password.is_empty() {
            return Ok(Self::Plaintext);
        }
        Self::validate_password_length(password)?;
        let mut salt = [0; SALT_LEN];
        SysRng
            .try_fill_bytes(&mut salt)
            .expect("Could not generate database encryption salt");
        Self::from_salt(password, salt)
    }

    fn validate_password_length(password: &[u8]) -> Result<(), DbCryptoError> {
        if password.len() != PASSWORD_LEN {
            return Err(DbCryptoError::InvalidPasswordLength);
        }
        Ok(())
    }

    fn from_salt(password: &[u8], salt: [u8; SALT_LEN]) -> Result<Self, DbCryptoError> {
        // Use RFC 9106's memory-constrained profile. Pin the parameters so changes
        // to library defaults cannot change v1 key derivation.
        let params = Params::new(64 * 1024, 3, 4, Some(KEY_LEN)).map_err(DbCryptoError::Argon2)?;
        let mut key = [0; KEY_LEN];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password, &[KEY_DOMAIN, salt.as_slice()].concat(), &mut key)
            .map_err(DbCryptoError::Argon2)?;
        Ok(Self::V1 { key, salt })
    }

    fn legacy(password: &[u8]) -> Result<Self, DbCryptoError> {
        Self::validate_password_length(password)?;
        let mut hasher = Blake2b512::new();
        hasher.update(LEGACY_DOMAIN);
        hasher.update(password);
        let digest = hasher.finalize();
        Ok(Self::Legacy {
            key: digest[..KEY_LEN].try_into().expect("32-byte key"),
            nonce: digest[KEY_LEN..KEY_LEN + NONCE_LEN]
                .try_into()
                .expect("12-byte nonce"),
        })
    }

    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, DbCryptoError> {
        match self {
            Self::Plaintext => Ok(plaintext.to_vec()),
            Self::Legacy { .. } => Err(DbCryptoError::MigrationRequired),
            Self::V1 { key, .. } => {
                let mut nonce = [0; NONCE_LEN];
                SysRng
                    .try_fill_bytes(&mut nonce)
                    .expect("Could not generate database encryption nonce");
                let cipher = Aes256Gcm::new(key.into());
                let encrypted = cipher.encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: plaintext,
                        aad: RECORD_AAD,
                    },
                )?;
                let mut value = Vec::with_capacity(1 + NONCE_LEN + encrypted.len());
                value.push(RECORD_VERSION);
                value.extend_from_slice(&nonce);
                value.extend_from_slice(&encrypted);
                Ok(value)
            }
        }
    }

    pub(crate) fn decrypt(&self, value: &[u8]) -> Result<Vec<u8>, DbCryptoError> {
        match self {
            Self::Plaintext => Ok(value.to_vec()),
            Self::Legacy { key, nonce } => {
                Ok(Aes256Gcm::new(key.into()).decrypt(nonce.into(), value)?)
            }
            Self::V1 { key, .. } => {
                if value.len() < 1 + NONCE_LEN + TAG_LEN || value[0] != RECORD_VERSION {
                    return Err(DbCryptoError::InvalidFormat);
                }
                Ok(Aes256Gcm::new(key.into()).decrypt(
                    (&value[1..1 + NONCE_LEN])
                        .try_into()
                        .map_err(|_| DbCryptoError::InvalidFormat)?,
                    Payload {
                        msg: &value[1 + NONCE_LEN..],
                        aad: RECORD_AAD,
                    },
                )?)
            }
        }
    }
}

/// Encryption state and metadata handle. Database owns this behind one RwLock;
/// callers hold its guard for the entire LMDB operation, including commit and
/// activation of a new context. Stores borrow this provider instead of sharing
/// independently accessible copies.
pub struct DbCryptoProvider {
    database: Database,
    format: CryptoFormat,
    encrypted: bool,
    context: Option<CryptoContext>,
}

impl DbCryptoProvider {
    pub(crate) fn new(env: &Environment, format: CryptoFormat) -> Result<Self, DbCryptoError> {
        let database = env.create_db(Some(CRYPTO_DB_NAME), DatabaseFlags::empty())?;
        let txn = env.begin_ro_txn()?;
        let encrypted = match txn.get(database, &ENCRYPTION_STATE_KEY) {
            Ok(_) => true,
            Err(LmdbError::NotFound) => false,
            Err(err) => return Err(err.into()),
        };
        if encrypted && format == CryptoFormat::V1 {
            Self::read_salt(database, &txn)?;
        }
        Ok(Self {
            database,
            format,
            encrypted,
            context: if encrypted {
                None
            } else {
                Some(CryptoContext::Plaintext)
            },
        })
    }

    fn read_salt(
        database: Database,
        txn: &impl Transaction,
    ) -> Result<[u8; SALT_LEN], DbCryptoError> {
        match txn.get(database, &KEY_SALT_KEY) {
            Ok(bytes) => bytes.try_into().map_err(|_| DbCryptoError::InvalidFormat),
            Err(LmdbError::NotFound) => Err(DbCryptoError::InvalidFormat),
            Err(err) => Err(err.into()),
        }
    }

    pub(crate) fn is_db_encrypted(&self) -> bool {
        self.encrypted
    }

    pub(crate) fn is_unlocked(&self) -> bool {
        self.context.is_some()
    }

    pub(crate) fn context(&self) -> Result<&CryptoContext, DbCryptoError> {
        self.context.as_ref().ok_or(DbCryptoError::PasswordNeeded)
    }

    /// Authenticate without unlocking the database. The caller can use the
    /// returned context for migration, and activate it only after a
    /// successful commit.
    pub(crate) fn validate_password(
        &self,
        txn: &impl Transaction,
        password: &[u8],
    ) -> Result<CryptoContext, DbCryptoError> {
        if !self.encrypted {
            return if password.is_empty() {
                Ok(CryptoContext::Plaintext)
            } else {
                Err(DbCryptoError::InvalidPassword)
            };
        }
        CryptoContext::validate_password_length(password)?;
        let context = match self.format {
            CryptoFormat::Legacy => CryptoContext::legacy(password)?,
            CryptoFormat::V1 => {
                CryptoContext::from_salt(password, Self::read_salt(self.database, txn)?)?
            }
        };
        let marker = txn.get(self.database, &ENCRYPTION_STATE_KEY)?;
        match context.decrypt(marker) {
            Ok(plaintext) if plaintext == ENCRYPTION_STATE_VAL => Ok(context),
            Err(DbCryptoError::InvalidFormat) => Err(DbCryptoError::InvalidFormat),
            _ => Err(DbCryptoError::InvalidPassword),
        }
    }

    /// Stage metadata in the same transaction as the monitor rewrites.
    pub(crate) fn write_metadata(
        &self,
        txn: &mut RwTransaction<'_>,
        context: &CryptoContext,
    ) -> Result<(), DbCryptoError> {
        match context {
            CryptoContext::Plaintext => {
                for key in [ENCRYPTION_STATE_KEY, KEY_SALT_KEY] {
                    match txn.del(self.database, &key, None) {
                        Ok(()) | Err(LmdbError::NotFound) => {}
                        Err(err) => return Err(err.into()),
                    }
                }
            }
            CryptoContext::V1 { salt, .. } => {
                let marker = context.encrypt(ENCRYPTION_STATE_VAL)?;
                txn.put(
                    self.database,
                    &ENCRYPTION_STATE_KEY,
                    &marker,
                    WriteFlags::empty(),
                )?;
                txn.put(self.database, &KEY_SALT_KEY, salt, WriteFlags::empty())?;
            }
            CryptoContext::Legacy { .. } => return Err(DbCryptoError::MigrationRequired),
        }
        Ok(())
    }

    /// Called only after commit (or validation of an already-current database),
    /// while Database still holds the provider's write guard.
    pub(crate) fn activate_context(&mut self, context: CryptoContext) {
        assert!(!matches!(context, CryptoContext::Legacy { .. }));
        self.format = CryptoFormat::V1;
        self.encrypted = !matches!(context, CryptoContext::Plaintext);
        self.context = Some(context);
    }

    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, DbCryptoError> {
        self.context()?.encrypt(plaintext)
    }

    pub(crate) fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DbCryptoError> {
        self.context()?.decrypt(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Nonce;
    use tempfile::TempDir;

    #[test]
    fn fresh_nonces_and_authenticated_envelopes() {
        const NONCE_START: usize = 1; // The nonce follows the version byte.
        const CIPHERTEXT_START: usize = NONCE_START + NONCE_LEN;
        const RECORD_OVERHEAD: usize = CIPHERTEXT_START + TAG_LEN;

        let context = CryptoContext::new(&[42; PASSWORD_LEN]).unwrap();
        for plaintext in [b"".as_slice(), b"true", b"monitor data"] {
            let first = context.encrypt(plaintext).unwrap();
            let second = context.encrypt(plaintext).unwrap();
            assert_eq!(first.len(), plaintext.len() + RECORD_OVERHEAD);
            assert_eq!(first[0], RECORD_VERSION);
            assert_ne!(
                first[NONCE_START..CIPHERTEXT_START],
                second[NONCE_START..CIPHERTEXT_START]
            );
            assert_eq!(context.decrypt(&first).unwrap(), plaintext);
            assert_eq!(context.decrypt(&second).unwrap(), plaintext);

            // Changing any envelope field must invalidate the record.
            let tag_start = first.len() - TAG_LEN;
            for (field, index) in [
                ("version", 0),
                ("nonce", NONCE_START),
                ("authentication tag", tag_start),
            ] {
                let mut modified = first.clone();
                modified[index] ^= 0x80;
                assert!(
                    context.decrypt(&modified).is_err(),
                    "tampered {field} was accepted"
                );
            }
            if !plaintext.is_empty() {
                let mut modified = first.clone();
                modified[CIPHERTEXT_START] ^= 0x80;
                assert!(
                    context.decrypt(&modified).is_err(),
                    "tampered ciphertext was accepted"
                );
            }

            for len in 0..RECORD_OVERHEAD {
                assert!(
                    context.decrypt(&first[..len]).is_err(),
                    "truncated record of length {len} was accepted"
                );
            }
        }

        let encrypted = context.encrypt(b"monitor data").unwrap();
        let wrong_password = CryptoContext::new(&[43; PASSWORD_LEN]).unwrap();
        assert!(wrong_password.decrypt(&encrypted).is_err());

        // A new context with the same password derives a new key from a fresh salt.
        let same_password_new_salt = CryptoContext::new(&[42; PASSWORD_LEN]).unwrap();
        assert!(same_password_new_salt.decrypt(&encrypted).is_err());
    }

    #[test]
    fn independent_wire_format_and_legacy_fixture() {
        // Fixed fixture generated by the pre-upgrade implementation (aes-gcm 0.10.3).
        let legacy_ciphertext = [
            0x3c, 0x5b, 0x8d, 0xc8, 0x25, 0xdf, 0xa9, 0xb1, 0x56, 0xc4, 0xde, 0xad, 0xb4, 0x05,
            0xae, 0x27, 0x69, 0xcd, 0xa6, 0x5d,
        ];
        let legacy = CryptoContext::legacy(&[42; PASSWORD_LEN]).unwrap();
        assert_eq!(legacy.decrypt(&legacy_ciphertext).unwrap(), b"true");
        assert!(matches!(
            legacy.encrypt(b"true"),
            Err(DbCryptoError::MigrationRequired)
        ));

        let salt = [9; SALT_LEN];
        // Generated independently with argon2-cffi: Argon2id v19, m=65536,
        // t=3, p=4, password=[42; 32], salt=b"mc_mobilecoind_db_v1" + [9; 32].
        let key = hex::decode("676b2285f4ad2cf4d6f08744b3634d77c3c7c4f8e9d2bdc3fa507630f0647b8d")
            .unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let context = CryptoContext::from_salt(&[42; PASSWORD_LEN], salt).unwrap();
        let value = context.encrypt(b"record").unwrap();
        assert_eq!(
            cipher
                .decrypt(
                    <&Nonce<Aes256Gcm>>::try_from(&value[1..13]).unwrap(),
                    Payload {
                        msg: &value[13..],
                        aad: b"mc_mobilecoind_db_v1\x01",
                    }
                )
                .unwrap(),
            b"record"
        );
        // Header/AAD stripping or legacy fallback must not authenticate.
        assert!(cipher
            .decrypt(
                <&Nonce<Aes256Gcm>>::try_from(&value[1..13]).unwrap(),
                &value[13..]
            )
            .is_err());
        assert!(context.decrypt(&legacy_ciphertext).is_err());
    }

    #[test]
    fn password_lengths() {
        for len in [1, 31, 33] {
            assert!(matches!(
                CryptoContext::new(&vec![42; len]),
                Err(DbCryptoError::InvalidPasswordLength)
            ));
        }
        assert!(matches!(
            CryptoContext::new(&[]).unwrap(),
            CryptoContext::Plaintext
        ));
        assert!(CryptoContext::new(&[42; 32]).is_ok());
    }

    #[test]
    fn provider_metadata_reopen_and_failed_validation_do_not_activate_context() {
        let path = TempDir::new().unwrap();
        let env = Environment::new()
            .set_max_dbs(10)
            .open(path.path())
            .unwrap();
        let mut provider = DbCryptoProvider::new(&env, CryptoFormat::V1).unwrap();
        assert!(provider.is_unlocked());
        assert!(!provider.is_db_encrypted());
        assert_eq!(provider.encrypt(b"plaintext").unwrap(), b"plaintext");
        let txn = env.begin_ro_txn().unwrap();
        assert!(provider.validate_password(&txn, &[42; 32]).is_err());
        drop(txn);

        let context = CryptoContext::new(&[42; 32]).unwrap();
        let encrypted = context.encrypt(b"plaintext").unwrap();
        let mut txn = env.begin_rw_txn().unwrap();
        provider.write_metadata(&mut txn, &context).unwrap();
        txn.commit().unwrap();
        provider.activate_context(context);
        let mut provider = DbCryptoProvider::new(&env, CryptoFormat::V1).unwrap();
        assert!(!provider.is_unlocked());
        assert!(provider.is_db_encrypted());
        assert!(provider.encrypt(b"plaintext").is_err());
        assert!(provider.decrypt(&encrypted).is_err());
        let txn = env.begin_ro_txn().unwrap();
        for password in [vec![], vec![1], vec![43; 32]] {
            assert!(provider.validate_password(&txn, &password).is_err());
            assert!(!provider.is_unlocked());
        }
        let candidate = provider.validate_password(&txn, &[42; 32]).unwrap();
        assert!(!provider.is_unlocked());
        drop(txn);
        provider.activate_context(candidate);
        assert_eq!(provider.decrypt(&encrypted).unwrap(), b"plaintext");
        let mut txn = env.begin_rw_txn().unwrap();
        provider
            .write_metadata(&mut txn, &CryptoContext::Plaintext)
            .unwrap();
        txn.commit().unwrap();
        provider.activate_context(CryptoContext::Plaintext);
        assert!(!provider.is_db_encrypted());
        assert_eq!(provider.decrypt(b"plaintext").unwrap(), b"plaintext");
        assert!(matches!(
            env.begin_ro_txn()
                .unwrap()
                .get(provider.database, &KEY_SALT_KEY),
            Err(LmdbError::NotFound)
        ));
    }

    #[test]
    fn malformed_salt_and_marker_fail_closed() {
        let path = TempDir::new().unwrap();
        let env = Environment::new()
            .set_max_dbs(10)
            .open(path.path())
            .unwrap();
        let provider = DbCryptoProvider::new(&env, CryptoFormat::V1).unwrap();
        let context = CryptoContext::new(&[42; 32]).unwrap();
        let mut txn = env.begin_rw_txn().unwrap();
        provider.write_metadata(&mut txn, &context).unwrap();
        txn.put(
            provider.database,
            &KEY_SALT_KEY,
            &[1; 31],
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();
        assert!(matches!(
            DbCryptoProvider::new(&env, CryptoFormat::V1),
            Err(DbCryptoError::InvalidFormat)
        ));
        let mut txn = env.begin_rw_txn().unwrap();
        provider.write_metadata(&mut txn, &context).unwrap();
        txn.put(
            provider.database,
            &ENCRYPTION_STATE_KEY,
            &b"bad marker",
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();
        let provider = DbCryptoProvider::new(&env, CryptoFormat::V1).unwrap();
        assert!(matches!(
            provider.validate_password(&env.begin_ro_txn().unwrap(), &[42; 32]),
            Err(DbCryptoError::InvalidFormat)
        ));
        assert!(!provider.is_unlocked());
        let mut txn = env.begin_rw_txn().unwrap();
        provider.write_metadata(&mut txn, &context).unwrap();
        txn.put(
            provider.database,
            &KEY_SALT_KEY,
            &[1; 32],
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();
        assert!(provider
            .validate_password(&env.begin_ro_txn().unwrap(), &[42; 32])
            .is_err());
        assert!(!provider.is_unlocked());
    }
}
