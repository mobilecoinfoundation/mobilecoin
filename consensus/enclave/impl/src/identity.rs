// Copyright (c) 2018-2021 The MobileCoin Foundation

/// Implementation of ed25519 signer identity for report
use mc_crypto_ake_enclave::EnclaveIdentity;
use mc_crypto_keys::{Ed25519Pair, Ed25519Public};
use mc_crypto_rand::McRng;
use mc_sgx_compat::sync::Mutex;
use mc_util_from_random::FromRandom;

pub struct Ed25519Identity {
    pub signing_keypair: Mutex<Ed25519Pair>,
}

impl Default for Ed25519Identity {
    fn default() -> Self {
        Self {
            signing_keypair: Mutex::new(Ed25519Pair::from_random(&mut McRng::default())),
        }
    }
}

impl Ed25519Identity {
    pub fn get_public_key(&self) -> Ed25519Public {
        let lock = self.signing_keypair.lock().unwrap();
        lock.public_key()
    }
}

impl EnclaveIdentity for Ed25519Identity {
    fn get_bytes_for_report(&self) -> [u8; 32] {
        *self.get_public_key().as_ref()
    }
}
