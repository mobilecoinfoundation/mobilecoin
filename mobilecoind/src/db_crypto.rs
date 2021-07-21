// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Helper for managing database encryption.

use aes_gcm::{
    aead::{
        generic_array::{sequence::Split, GenericArray},
        Aead,
    },
    AeadCore, Aes256Gcm, Error as AeadError, NewAead,
};
use blake2::{Blake2b, Digest};
use displaydoc::Display;
use lmdb::{
    Database, DatabaseFlags, Environment, Error as LmdbError, RwTransaction, Transaction,
    WriteFlags,
};
use std::sync::{Arc, Mutex};

/// Domain tag for database-wide encryption.
pub const MOBILECOIND_DB_KEY_DOMAIN_TAG: &str = "mc_mobilecoind";

/// Required password length.
/// This is set to 32 bytes as the intended purpose is for the user to pass a
/// hash of a password and not the actual password the user typed.
pub const PASSWORD_LEN: usize = 32;

/// LMDB database name for storing metadata.
const CRYPTO_DB_NAME: &str = "db_crypto";

/// Key/value used for testing we have the correct encryption key.
const ENCRYPTION_STATE_KEY: &str = "db_encrypted";
const ENCRYPTION_STATE_VAL: &str = "true";

/// Possible db crypto error types.
#[derive(Debug, Display)]
pub enum DbCryptoError {
    /// Invalid password length
    InvalidPasswordLength,

    /// Invalid password
    InvalidPassword,

    /// Password needed
    PasswordNeeded,

    /// AEAD: {0}
    Aead(AeadError),

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

/// Database crypto state that is shared between multiple threads.
struct DbCryptoProviderState {
    /// Is the database currently encrypted?
    is_db_encrypted: bool,

    /// The current encryption key, stored inside Arc/Mutex so that this object
    /// could be safely shared.
    /// This should only be set once the password has been determined to be
    /// valid!
    encryption_key: Vec<u8>,
}

/// Database encryption helper.
#[derive(Clone)]
pub struct DbCryptoProvider {
    /// LMDB Environment (database).
    env: Arc<Environment>,

    /// Database used for testing whether we have the correct encryption key or
    /// not.
    database: Database,

    /// Shared state.
    state: Arc<Mutex<DbCryptoProviderState>>,
}

impl DbCryptoProvider {
    pub fn new(env: Arc<Environment>) -> Result<Self, DbCryptoError> {
        let database = env.create_db(Some(CRYPTO_DB_NAME), DatabaseFlags::empty())?;

        // Check if the database is currently encrypted.
        let is_db_encrypted = {
            let db_txn = env.begin_ro_txn()?;
            match db_txn.get(database, &ENCRYPTION_STATE_KEY.as_bytes()) {
                Ok(_test_val) => {
                    // The encryption indicator key is present in the database, this means
                    // encryption is enabled.
                    true
                }
                Err(LmdbError::NotFound) => {
                    // The encryption indicator key is not in the database, this means encryption is
                    // not enabled.
                    false
                }
                Err(err) => {
                    return Err(err.into());
                }
            }
        };

        Ok(Self {
            env,
            database,
            state: Arc::new(Mutex::new(DbCryptoProviderState {
                is_db_encrypted,
                encryption_key: vec![],
            })),
        })
    }

    /// Check if data is currently being encrypted.
    pub fn is_db_encrypted(&self) -> bool {
        let state = self.state.lock().expect("mutex poisoned");
        state.is_db_encrypted
    }

    /// Check if a given password is the password used to encrypt data in the
    /// db, and if so store it for future encryption/decryption operations.
    pub fn check_and_store_password(&self, password: &[u8]) -> Result<(), DbCryptoError> {
        let mut state = self.state.lock().expect("mutex poisoned");
        if state.is_db_encrypted {
            // Database is encrypted, see if we can decrypt our test value with the provided
            // password.
            let db_txn = self.env.begin_ro_txn()?;
            let test_val = db_txn.get(self.database, &ENCRYPTION_STATE_KEY.as_bytes())?;
            let expected_val =
                self.encrypt_with_password(password, ENCRYPTION_STATE_VAL.as_bytes())?;
            if test_val == expected_val {
                state.encryption_key = password.to_vec();
                Ok(())
            } else {
                Err(DbCryptoError::InvalidPassword)
            }
        } else {
            // Db is not encrypted, password should be empty.
            if password.is_empty() {
                assert!(state.encryption_key.is_empty());
                Ok(())
            } else {
                Err(DbCryptoError::InvalidPassword)
            }
        }
    }

    /// Check if the database has been "unlocked" - meaning, whether we are able
    /// to successfully decrypt data using the information in our state
    /// object.
    pub fn is_unlocked(&self) -> bool {
        let state = self.state.lock().expect("mutex poisoned");
        if state.is_db_encrypted {
            // We're encrypted, and only unlocked if a password has been provided.
            !state.encryption_key.is_empty()
        } else {
            // Not encrypted, so we're always unlocked. Sanity check that the key is empty.
            assert!(state.encryption_key.is_empty());
            true
        }
    }

    /// Change the password that will be used for all future
    /// encryption/decryption operations. This should only be called after
    /// all existing data has been re-encrypted to the new password!
    pub fn change_password<'env>(
        &self,
        mut db_txn: RwTransaction<'env>,
        password: &[u8],
    ) -> Result<(), DbCryptoError> {
        let mut state = self.state.lock().expect("muted poisoned");

        // The test value will be used to verify whether a given password is correct.
        if password.is_empty() {
            if state.is_db_encrypted {
                db_txn.del(self.database, &ENCRYPTION_STATE_KEY.as_bytes(), None)?;
            }
        } else {
            if password.len() != PASSWORD_LEN {
                return Err(DbCryptoError::InvalidPasswordLength);
            }

            db_txn.put(
                self.database,
                &ENCRYPTION_STATE_KEY.as_bytes(),
                &self.encrypt_with_password(password, ENCRYPTION_STATE_VAL.as_bytes())?,
                WriteFlags::empty(),
            )?;
        }

        db_txn.commit()?;

        if password.is_empty() {
            state.is_db_encrypted = false;
            state.encryption_key = vec![];
        } else {
            state.is_db_encrypted = true;
            state.encryption_key = password.to_vec();
        }

        Ok(())
    }

    /// Encrypt data with the currently set password.
    pub fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, DbCryptoError> {
        let state = self.state.lock().expect("mutex poisoned");
        if state.is_db_encrypted {
            if state.encryption_key.is_empty() {
                return Err(DbCryptoError::PasswordNeeded);
            }

            let (key, nonce) = Self::expand_password(&state.encryption_key)?;

            let cipher = Aes256Gcm::new(&key);

            Ok(cipher.encrypt(&nonce, plaintext_bytes)?)
        } else {
            Ok(plaintext_bytes.to_vec())
        }
    }

    /// Encrypt data with a specific password.
    /// This is used when we want to re-encrypt data as a result of a password
    /// change: 1. Go over all encrypted data, decrypt it with the current
    /// password and re-encrypt with the    new password using this method.
    /// 2. Once all data has been re-encrypted, call set_password so that future
    /// operations use the    new password.
    pub fn encrypt_with_password(
        &self,
        password: &[u8],
        plaintext_bytes: &[u8],
    ) -> Result<Vec<u8>, DbCryptoError> {
        // Short-circuit when no password is being used.
        if password.is_empty() {
            return Ok(plaintext_bytes.to_vec());
        }

        if password.len() != PASSWORD_LEN {
            return Err(DbCryptoError::InvalidPasswordLength);
        }

        let (key, nonce) = Self::expand_password(password)?;

        let cipher = Aes256Gcm::new(&key);
        Ok(cipher.encrypt(&nonce, plaintext_bytes)?)
    }

    /// Decrypt data with the currently set password.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DbCryptoError> {
        let state = self.state.lock().expect("mutex poisoned");

        // There are two scenarios in which a password won't be set:
        // 1) When the db is not being encrypted, in which case we just return the
        //    ciphertext back to the caller.
        // 2) When the db is encrypted but has not yet been unlocked by calling
        //    check_and_store_password. In order to provide a better user experience, we
        //    test if that is the case before assuming no password is required.
        //    This allows callers to get a meaningful error (PasswordNeeded) instead of
        //    prost decode errors.
        match (state.is_db_encrypted, state.encryption_key.is_empty()) {
            // Db is not encrypted and password is empty
            (false, true) => Ok(ciphertext.to_vec()),

            // Db is not encrypted and password is not empty (should never happen)
            (false, false) => panic!("invalid db encryption state"),

            // Db is encrypted but password is missing
            (true, true) => Err(DbCryptoError::PasswordNeeded),

            // Db is encrypted and we have a password
            (true, false) => {
                let (key, nonce) = Self::expand_password(&state.encryption_key)?;

                let cipher = Aes256Gcm::new(&key);

                Ok(cipher.decrypt(&nonce, ciphertext)?)
            }
        }
    }

    /// Expands the password into an encryption key and a nonce.
    fn expand_password(
        password: &[u8],
    ) -> Result<
        (
            GenericArray<u8, <Aes256Gcm as NewAead>::KeySize>,
            GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize>,
        ),
        DbCryptoError,
    > {
        // Hash the password hash with Blake2b to get 64 bytes, first 32 for aeskey,
        // second 32 for nonce
        let mut hasher = Blake2b::new();
        hasher.update(&MOBILECOIND_DB_KEY_DOMAIN_TAG);
        hasher.update(&password);
        let result = hasher.finalize();

        let (key, remainder) = Split::<u8, <Aes256Gcm as NewAead>::KeySize>::split(result);
        let (nonce, _remainder) = Split::<u8, <Aes256Gcm as AeadCore>::NonceSize>::split(remainder);

        Ok((key, nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;
    const TEST_DATA: &[u8; 10] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    fn get_test_db_crypto_provider() -> (DbCryptoProvider, TempDir) {
        let path = TempDir::new("db_crypto_test").expect("Could not make tempdir for ledger db");

        let env = Arc::new(
            Environment::new()
                .set_max_dbs(10)
                .set_map_size(10000000)
                .open(path.as_ref())
                .unwrap(),
        );

        (DbCryptoProvider::new(env).unwrap(), path)
    }

    #[test]
    fn test_basic() {
        let (crypto_provider, _) = get_test_db_crypto_provider();

        // We start un-encrypted and unlocked.
        assert!(!crypto_provider.is_db_encrypted());
        assert!(crypto_provider.is_unlocked());

        // check_and_store_password should only accept an empty password and we should
        // stay unencrypted.
        assert!(crypto_provider
            .check_and_store_password(&[1, 2, 3])
            .is_err());
        assert!(!crypto_provider.is_db_encrypted());
        assert!(crypto_provider.is_unlocked());

        assert!(crypto_provider.check_and_store_password(&[]).is_ok());
        assert!(!crypto_provider.is_db_encrypted());
        assert!(crypto_provider.is_unlocked());

        // Encrypting/decrypting should be a no-op at this point.
        assert_eq!(
            crypto_provider.encrypt(&TEST_DATA[..]).unwrap(),
            TEST_DATA.to_vec()
        );
        assert_eq!(
            crypto_provider.decrypt(&TEST_DATA[..]).unwrap(),
            TEST_DATA.to_vec()
        );
        assert_eq!(
            crypto_provider
                .encrypt_with_password(&[], &TEST_DATA[..])
                .unwrap(),
            TEST_DATA.to_vec()
        );
        assert_ne!(
            crypto_provider
                .encrypt_with_password(&[1; PASSWORD_LEN], &TEST_DATA[..])
                .unwrap(),
            TEST_DATA.to_vec()
        );

        // Changing to empty password should not affect anything.
        let db_txn = crypto_provider.env.begin_rw_txn().unwrap();
        crypto_provider.change_password(db_txn, &[]).unwrap();

        assert!(crypto_provider
            .check_and_store_password(&[1, 2, 3])
            .is_err());
        assert!(!crypto_provider.is_db_encrypted());
        assert!(crypto_provider.is_unlocked());

        assert!(crypto_provider.check_and_store_password(&[]).is_ok());
        assert!(crypto_provider.check_and_store_password(&[200; 1]).is_err());
        assert!(crypto_provider
            .check_and_store_password(&[200; PASSWORD_LEN])
            .is_err());
        assert!(!crypto_provider.is_db_encrypted());
        assert!(crypto_provider.is_unlocked());

        // Encrypting/decrypting should be a no-op at this point.
        assert_eq!(
            crypto_provider.encrypt(&TEST_DATA[..]).unwrap(),
            TEST_DATA.to_vec()
        );
        assert_eq!(
            crypto_provider.decrypt(&TEST_DATA[..]).unwrap(),
            TEST_DATA.to_vec()
        );
        assert_eq!(
            crypto_provider
                .encrypt_with_password(&[], &TEST_DATA[..])
                .unwrap(),
            TEST_DATA.to_vec()
        );
        assert_ne!(
            crypto_provider
                .encrypt_with_password(&[1; PASSWORD_LEN], &TEST_DATA[..])
                .unwrap(),
            TEST_DATA.to_vec()
        );

        // Changing a password should indicate we are now encrypted, and
        // encryption/decryption should no longer be the identity function.
        let db_txn = crypto_provider.env.begin_rw_txn().unwrap();
        crypto_provider
            .change_password(db_txn, &[6; PASSWORD_LEN])
            .unwrap();

        assert!(crypto_provider.check_and_store_password(&[]).is_err());
        assert!(crypto_provider.check_and_store_password(&[200; 1]).is_err());
        assert!(crypto_provider
            .check_and_store_password(&[200; PASSWORD_LEN])
            .is_err());
        assert!(crypto_provider
            .check_and_store_password(&[6; PASSWORD_LEN])
            .is_ok());

        assert!(crypto_provider.is_db_encrypted());
        assert!(crypto_provider.is_unlocked());

        let encrypted_data = crypto_provider.encrypt(&TEST_DATA[..]).unwrap();
        assert_ne!(encrypted_data, TEST_DATA.to_vec()); // No longer the identity function
        assert!(crypto_provider.decrypt(&TEST_DATA[..]).is_err()); // TEST_DATA is not encrypted so this shoud fail.
        assert_eq!(
            TEST_DATA.to_vec(),
            crypto_provider.decrypt(&encrypted_data).unwrap()
        );

        assert_eq!(
            encrypted_data,
            crypto_provider
                .encrypt_with_password(&[6; PASSWORD_LEN], &TEST_DATA[..])
                .unwrap()
        );

        // Changing to a different password should result in different encrypted data.
        let db_txn = crypto_provider.env.begin_rw_txn().unwrap();
        crypto_provider
            .change_password(db_txn, &[7; PASSWORD_LEN])
            .unwrap();

        assert!(crypto_provider.is_db_encrypted());
        assert!(crypto_provider.is_unlocked());

        let encrypted_data2 = crypto_provider.encrypt(&TEST_DATA[..]).unwrap();
        assert_ne!(encrypted_data, encrypted_data2);
        assert_ne!(TEST_DATA.to_vec(), encrypted_data2);

        assert_eq!(
            encrypted_data2,
            crypto_provider
                .encrypt_with_password(&[7; PASSWORD_LEN], &TEST_DATA[..])
                .unwrap()
        );

        // Previously encrypted data should not decrypt.
        assert!(crypto_provider.decrypt(&encrypted_data).is_err());

        // check_and_store_password should behave as expected.
        assert!(crypto_provider.check_and_store_password(&[]).is_err());
        assert!(crypto_provider.check_and_store_password(&[200; 1]).is_err());
        assert!(crypto_provider
            .check_and_store_password(&[200; PASSWORD_LEN])
            .is_err());
        assert!(crypto_provider
            .check_and_store_password(&[7; PASSWORD_LEN])
            .is_ok());

        // Changing back to an empty password should clear the is_db_encrypted flag.
        let db_txn = crypto_provider.env.begin_rw_txn().unwrap();
        crypto_provider.change_password(db_txn, &[]).unwrap();

        assert!(crypto_provider.check_and_store_password(&[]).is_ok());
        assert!(!crypto_provider.is_db_encrypted());
        assert!(crypto_provider.is_unlocked());

        // Encrypting/decrypting should be a no-op at this point.
        assert_eq!(
            crypto_provider.encrypt(&TEST_DATA[..]).unwrap(),
            TEST_DATA.to_vec()
        );
        assert_eq!(
            crypto_provider.decrypt(&TEST_DATA[..]).unwrap(),
            TEST_DATA.to_vec()
        );
        assert_eq!(
            crypto_provider
                .encrypt_with_password(&[], &TEST_DATA[..])
                .unwrap(),
            TEST_DATA.to_vec()
        );
        assert_ne!(
            crypto_provider
                .encrypt_with_password(&[1; PASSWORD_LEN], &TEST_DATA[..])
                .unwrap(),
            TEST_DATA.to_vec()
        );

        // check_and_store_password should behave as expected.
        assert!(crypto_provider.check_and_store_password(&[]).is_ok());
        assert!(crypto_provider.check_and_store_password(&[200; 1]).is_err());
        assert!(crypto_provider
            .check_and_store_password(&[200; PASSWORD_LEN])
            .is_err());
        assert!(crypto_provider.check_and_store_password(&[7; 1]).is_err());
    }

    #[test]
    fn test_encrypt_with_password_rejects_invalid_password_len() {
        let (crypto_provider, _) = get_test_db_crypto_provider();

        assert!(crypto_provider
            .encrypt_with_password(&[123; PASSWORD_LEN - 1], &TEST_DATA[..])
            .is_err());

        assert!(crypto_provider
            .encrypt_with_password(&[123; PASSWORD_LEN + 1], &TEST_DATA[..])
            .is_err());

        assert!(crypto_provider
            .encrypt_with_password(&[123; PASSWORD_LEN], &TEST_DATA[..])
            .is_ok());
    }

    #[test]
    fn test_change_password_rejects_invalid_password_len() {
        let (crypto_provider, _) = get_test_db_crypto_provider();

        assert!(crypto_provider
            .change_password(
                crypto_provider.env.begin_rw_txn().unwrap(),
                &[123; PASSWORD_LEN - 1]
            )
            .is_err());

        assert!(crypto_provider
            .change_password(
                crypto_provider.env.begin_rw_txn().unwrap(),
                &[123; PASSWORD_LEN + 1]
            )
            .is_err());

        assert!(crypto_provider
            .change_password(
                crypto_provider.env.begin_rw_txn().unwrap(),
                &[123; PASSWORD_LEN]
            )
            .is_ok());
    }

    #[test]
    fn test_db_reopen() {
        // Get the initial db.
        let (_crypto_provider, path) = get_test_db_crypto_provider();

        let mut password = [0; PASSWORD_LEN];

        // We will toggle the encrytpion every other iteraction.
        // Even executions are un-encrypted, odd executions are encrypted.
        for i in 0..100 {
            let is_encrypted = i % 2 == 1;

            let env = Arc::new(
                Environment::new()
                    .set_max_dbs(10)
                    .set_map_size(10000000)
                    .open(path.as_ref())
                    .unwrap(),
            );

            let crypto_provider = DbCryptoProvider::new(env).unwrap();

            if is_encrypted {
                let expected_encrypted_bytes = crypto_provider
                    .encrypt_with_password(&password[..], &TEST_DATA[..])
                    .unwrap();

                assert!(crypto_provider.is_db_encrypted());
                assert!(!crypto_provider.is_unlocked());

                // encrypt/decrypt should fail if a password is not provided.
                assert!(crypto_provider.encrypt(&TEST_DATA[..]).is_err());
                assert!(crypto_provider.decrypt(&expected_encrypted_bytes).is_err());

                // Providing the wrong password should fail.
                assert!(crypto_provider
                    .check_and_store_password(&[255; PASSWORD_LEN])
                    .is_err());

                assert!(crypto_provider.is_db_encrypted());
                assert!(!crypto_provider.is_unlocked());

                // encrypt/decrypt should fail if a password is not provided.
                assert!(crypto_provider.encrypt(&TEST_DATA[..]).is_err());
                assert!(crypto_provider.decrypt(&expected_encrypted_bytes).is_err());

                // Provide the correct password
                crypto_provider
                    .check_and_store_password(&password[..])
                    .unwrap();

                assert!(crypto_provider.is_db_encrypted());
                assert!(crypto_provider.is_unlocked());

                assert_eq!(
                    crypto_provider.encrypt(&TEST_DATA[..]).unwrap(),
                    expected_encrypted_bytes
                );
                assert_eq!(
                    crypto_provider.decrypt(&expected_encrypted_bytes).unwrap(),
                    TEST_DATA.to_vec()
                );

                // Remove password
                crypto_provider
                    .change_password(crypto_provider.env.begin_rw_txn().unwrap(), &[])
                    .unwrap();
            } else {
                assert!(!crypto_provider.is_db_encrypted());
                assert!(crypto_provider.is_unlocked());

                assert_eq!(
                    crypto_provider.encrypt(&TEST_DATA[..]).unwrap(),
                    TEST_DATA.to_vec()
                );
                assert_eq!(
                    crypto_provider.decrypt(&TEST_DATA[..]).unwrap(),
                    TEST_DATA.to_vec()
                );
                assert_eq!(
                    crypto_provider
                        .encrypt_with_password(&[], &TEST_DATA[..])
                        .unwrap(),
                    TEST_DATA.to_vec()
                );
                assert_ne!(
                    crypto_provider
                        .encrypt_with_password(&[1; PASSWORD_LEN], &TEST_DATA[..])
                        .unwrap(),
                    TEST_DATA.to_vec()
                );

                // Encrypt for the next iteration.
                password = [i; PASSWORD_LEN];
                crypto_provider
                    .change_password(crypto_provider.env.begin_rw_txn().unwrap(), &password[..])
                    .unwrap();
            }
        }
    }
}
