// Copyright (c) 2018-2022 The MobileCoin Foundation

use super::RngCore;
use rand_core::{impls, CryptoRng, Error};

// A implementation of RngCore which wraps calls to getrandom,
// which provides a wrapper around https://github.com/WebAssembly/WASI/blob/main/phases/snapshot/docs.md#-random_getbuf-pointeru8-buf_len-size---result-errno
#[derive(Default)]
pub struct McRng;

impl CryptoRng for McRng {}

// See docu e.g.: https://docs.rs/rand_core/0.3.0/rand_core/trait.RngCore.html
impl RngCore for McRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if let Err(e) = self.try_fill_bytes(dest) {
            panic!("Error: {}", e);
        }
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        getrandom::getrandom(dest).map_err(|e| e.code())?;
        Ok(())
    }
}
