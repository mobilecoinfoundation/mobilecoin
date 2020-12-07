// Copyright (c) 2018-2020 MobileCoin Inc.

//! Helper for managing database encryption.

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, Error as AeadError, NewAead},
    Aes256Gcm,
};
use blake2::{Blake2b, Digest};
use failure::Fail;
use std::sync::{Arc, Mutex};

// Domain tag for database-wide encryption.
pub const MOBILECOIND_DB_KEY_DOMAIN_TAG: &str = "mc_account_key";

/// Possible db crypto error types.
#[derive(Debug, Fail)]
pub enum DbCryptoError {
    #[fail(display = "Database is encrypted and encryption key has not yet been provided")]
    MissingEncryptionKey,

    #[fail(display = "Database encryption not enabled")]
    EncryptionNotEnabled,

    #[fail(display = "Encryption key already set")]
    EncryptionKeyAlreadySet,

    #[fail(display = "Invalid encryption key length")]
    EncryptionInvalidKeyLength,

    #[fail(display = "AEAD error: {}", _0)]
    Aead(AeadError),
}

impl From<AeadError> for DbCryptoError {
    fn from(src: AeadError) -> Self {
        Self::Aead(src)
    }
}

/// Interface for database encryption support.
pub trait DbCryptoProvider: Clone {
    /// Sets the password to use.
    fn set_password(&self, password: &[u8]) -> Result<(), DbCryptoError>;

    /// Clear the password.
    fn clear_password(&self) -> Result<(), DbCryptoError>;

    /// Whether a password is needed or not (allows us to tell if we're running with an encryption
    /// backend or without).
    fn requires_password(&self) -> bool;

    /// Encrypt data.
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, DbCryptoError>;

    /// Decrypt data.
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, DbCryptoError>;
}

/// A no-op crypto provider, used when encryption is disabled.
#[derive(Clone, Default)]
pub struct NullDbCryptoProvider;

impl DbCryptoProvider for NullDbCryptoProvider {
    /// Sets the password to use.
    fn set_password(&self, _password: &[u8]) -> Result<(), DbCryptoError> {
        Err(DbCryptoError::EncryptionNotEnabled)
    }

    /// Clear the password.
    fn clear_password(&self) -> Result<(), DbCryptoError> {
        Err(DbCryptoError::EncryptionNotEnabled)
    }

    /// Whether a password is needed or not (allows us to tell if we're running with an encryption
    /// backend or without).
    fn requires_password(&self) -> bool {
        false
    }

    /// Encrypt data.
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, DbCryptoError> {
        Ok(data.to_vec())
    }

    /// Decrypt data.
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, DbCryptoError> {
        Ok(data.to_vec())
    }
}

/// Aes crypto provider
#[derive(Clone)]
pub struct AesDbCryptoProvider {
    encryption_key: Arc<Mutex<Option<Vec<u8>>>>,
}

impl Default for AesDbCryptoProvider {
    fn default() -> Self {
        Self {
            encryption_key: Arc::new(Mutex::new(None)),
        }
    }
}

impl DbCryptoProvider for AesDbCryptoProvider {
    /// Sets the password to use.
    /// The password needs to be 32 bytes - the intended purpose is for this to be a hash of the
    /// password and not the actual password the user typed.
    fn set_password(&self, password: &[u8]) -> Result<(), DbCryptoError> {
        let mut encryption_key = self.encryption_key.lock().expect("muted poisoned");
        if encryption_key.is_some() {
            Err(DbCryptoError::EncryptionKeyAlreadySet)
        } else if password.len() != 32 {
            Err(DbCryptoError::EncryptionInvalidKeyLength)
        } else {
            *encryption_key = Some(password.to_vec());
            Ok(())
        }
    }

    /// Clear the password.
    fn clear_password(&self) -> Result<(), DbCryptoError> {
        let mut encryption_key = self.encryption_key.lock().expect("muted poisoned");
        *encryption_key = None;
        Ok(())
    }

    /// Whether a password is needed or not (allows us to tell if we're running with an encryption
    /// backend or without).
    fn requires_password(&self) -> bool {
        true
    }

    /// Encrypt data.
    fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, DbCryptoError> {
        let (key, nonce) = self.expand_password()?;

        let key_arr = GenericArray::from_slice(&key[..]);
        let nonce_arr = GenericArray::from_slice(&nonce[..]);

        // Get cipher from hash bytes
        let cipher = Aes256Gcm::new(key_arr);

        Ok(cipher.encrypt(nonce_arr, &plaintext_bytes[..])?)
    }

    /// Decrypt data.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DbCryptoError> {
        let (key, nonce) = self.expand_password()?;
        let key_arr = GenericArray::from_slice(&key[..]);
        let nonce_arr = GenericArray::from_slice(&nonce[..]);

        let cipher = Aes256Gcm::new(key_arr);
        Ok(cipher.decrypt(nonce_arr, ciphertext)?)
    }
}

impl AesDbCryptoProvider {
    /// Get the encryption key if available, or an error if one is needed and hasn't been provided
    /// yet.
    fn get_encryption_key(&self) -> Result<Vec<u8>, DbCryptoError> {
        let encryption_key = self.encryption_key.lock().expect("muted poisoned");
        encryption_key
            .clone()
            .ok_or(DbCryptoError::MissingEncryptionKey)
    }

    /// Expands the password into an encryption key and a nonce.
    fn expand_password(&self) -> Result<([u8; 32], [u8; 12]), DbCryptoError> {
        let password = self.get_encryption_key()?;

        // Hash the password hash with Blake2b to get 64 bytes, first 32 for aeskey, second 32 for nonce
        let mut hasher = Blake2b::new();
        hasher.update(&MOBILECOIND_DB_KEY_DOMAIN_TAG);
        hasher.update(&password);
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        let result = hasher.finalize();
        key[..32].copy_from_slice(&result.as_slice()[..32]);
        // Nonce is 96 bits
        nonce[..12].copy_from_slice(&result.as_slice()[32..44]);

        Ok((key, nonce))
    }
}
