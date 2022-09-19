// Copyright (c) 2018-2022 The MobileCoin Foundation

use rand::{thread_rng, CryptoRng, Error, RngCore};

#[derive(Clone, Debug, Default)]
pub struct McRng;

impl RngCore for McRng {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        thread_rng().next_u32()
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        thread_rng().next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        thread_rng().fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        thread_rng().try_fill_bytes(dest)
    }
}

impl CryptoRng for McRng {}
