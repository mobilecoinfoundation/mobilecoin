// Copyright (c) 2018-2020 MobileCoin Inc.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod common;

cfg_if::cfg_if! {
    if #[cfg(feature="std")] {
        // Untrusted code
        mod untrusted;
        pub use untrusted::*;
    } else {
        // Enclave
        mod trusted;
        pub use trusted::*;
    }
}
