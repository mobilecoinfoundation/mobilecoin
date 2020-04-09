// Copyright (c) 2018-2020 MobileCoin Inc.

/// Implementation of ed25519 signer identity for report
use ake_enclave::EnclaveIdentity;
use keys::{Ed25519Pair, Ed25519Public, FromRandom};
use mcrand::McRng;
use sgx_compat::sync::Mutex;

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
