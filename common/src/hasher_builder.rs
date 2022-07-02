// Copyright (c) 2018-2022 The MobileCoin Foundation

//! This file provides [HasherBuilder], used in `mc_common::HashMap`
//! in and out of the enclave.

use core::hash::BuildHasher;
use mc_crypto_rand::McRng;
use rand_core::RngCore;
use siphasher::sip::SipHasher13;

/// A `no_std`-compatible [BuildHasher] using [McRng].
#[derive(Clone)]
pub struct HasherBuilder {
    k0: u64,
    k1: u64,
}

impl Default for HasherBuilder {
    fn default() -> Self {
        let mut rng = McRng::default();
        let k0 = rng.next_u64();
        let k1 = rng.next_u64();
        Self { k0, k1 }
    }
}

impl BuildHasher for HasherBuilder {
    type Hasher = SipHasher13;

    #[inline]
    fn build_hasher(&self) -> SipHasher13 {
        SipHasher13::new_with_keys(self.k0, self.k1)
    }
}
