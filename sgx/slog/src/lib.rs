// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]

extern crate alloc;

mod common;
pub use common::EnclaveLogMessage;

cfg_if::cfg_if! {
    if #[cfg(target_env="sgx")] {
        mod trusted;
        pub use trusted::*;
    }
}
