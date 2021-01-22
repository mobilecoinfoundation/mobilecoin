// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains objects and methods for communicating with the
//! Remote Attestation Services.

extern crate alloc;
extern crate core;

mod traits;

pub use self::traits::{Error, RaClient, Result};

#[cfg(not(feature = "sgx-sim"))]
mod ias;
#[cfg(feature = "sgx-sim")]
mod sim;

// Export the "build-configured" RaClient so that downstream doesn't need
// to copy paste this cfg_if every where and have a build.rs unnecessarily
cfg_if::cfg_if! {
    if #[cfg(feature = "sgx-sim")] {
        pub type Client = crate::sim::SimClient;
    } else {
        pub type Client = crate::ias::IasClient;
    }
}
