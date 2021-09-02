// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Implementation of ed25519 signer identity for report

use mc_crypto_ake_enclave::EnclaveIdentity;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_rand::McRng;
use mc_sgx_compat::sync::Mutex;
use mc_util_from_random::FromRandom;

/// An enclave identity based on a ristretto private key
pub struct RistrettoIdentity {
    /// Mutex guarding the private key to allow interior mutability
    pub private_key: Mutex<RistrettoPrivate>,
}

impl Default for RistrettoIdentity {
    fn default() -> Self {
        Self {
            private_key: Mutex::new(RistrettoPrivate::from_random(&mut McRng::default())),
        }
    }
}

impl RistrettoIdentity {
    /// Get the associated public key
    pub fn get_public_key(&self) -> RistrettoPublic {
        let lock = self.private_key.lock().unwrap();
        RistrettoPublic::from(&*lock)
    }
}

impl EnclaveIdentity for RistrettoIdentity {
    /// Get the bytes for the IAS report
    fn get_bytes_for_report(&self) -> [u8; 32] {
        self.get_public_key().to_bytes()
    }
}
