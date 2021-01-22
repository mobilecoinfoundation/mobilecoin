// Copyright (c) 2018-2021 The MobileCoin Foundation

// Note: This module is only expected to compile on x86 and x86_64

use super::RngCore;
use rand_core::{impls, CryptoRng, Error};

mod retry;

// A implementation of RngCore which wraps calls to RDRAND instruction
// Should work in enclave and out of enclave with no changes
#[derive(Default)]
pub struct McRng;

impl CryptoRng for McRng {}

// See docu e.g.: https://docs.rs/rand_core/0.3.0/rand_core/trait.RngCore.html
impl RngCore for McRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        retry::next_rdrand_u32_or_panic()
    }

    // On x86_64 use the rdrand64_step instruction,
    // on x86 use `impls::next_u64_via_u32` which generically makes a u64 from
    // two u32s
    #[inline]
    fn next_u64(&mut self) -> u64 {
        #[cfg(target_arch = "x86")]
        return impls::next_u64_via_u32(self);
        #[cfg(target_arch = "x86_64")]
        return retry::next_rdrand_u64_or_panic();
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
