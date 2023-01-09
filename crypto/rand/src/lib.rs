// Copyright (c) 2018-2022 The MobileCoin Foundation

#![no_std]

pub extern crate rand_core;

pub use rand_core::{CryptoRng, RngCore};

use cfg_if::cfg_if;

// Not using cfg_attr( ..., path = fallback.rs) because it appears to confuse
// rustfmt
cfg_if! {
    // rdrand if enabled
    if #[cfg(target_feature = "rdrand")] {
        mod rdrandrng;
        pub use rdrandrng::McRng;
    // OsRng for WASM
    } else if #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
        mod wasm;
        pub use wasm::McRng;
    // thread_rng if we have std
    } else if #[cfg(feature = "std")] {
        mod fallback;
        pub use fallback::McRng;
    // OsRng otherwise
    } else {
        mod wasm;
        pub use wasm::McRng;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_entropy_32() {
        let first_result = McRng::default().next_u32();
        for _ in 0..50 {
            let result = McRng::default().next_u32();
            if result != first_result {
                return;
            }
        }
        panic!("Got the same u32 50 times in a row: {}", first_result);
    }

    #[test]
    fn test_entropy_64() {
        let first_result = McRng::default().next_u64();
        for _ in 0..50 {
            let result = McRng::default().next_u64();
            if result != first_result {
                return;
            }
        }
        panic!("Got the same u64 50 times in a row: {}", first_result);
    }

    #[test]
    fn test_not_filled() {
        let result = McRng::default().next_u32();
        if result == 0 || result == 0xFFFF_FFFFu32 {
            panic!("Result should never be 0 or 0xFFFFFFFFu32");
        }
        let result = McRng::default().next_u64();
        if result == 0 || result == 0xFFFF_FFFF_FFFF_FFFFu64 {
            panic!("Result should never be 0 or 0xFFFFFFFFFFFFFFFFu64");
        }
    }
}
