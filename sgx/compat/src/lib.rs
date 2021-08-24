// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Compatibility layer for the use of sgx, meant to suport unit testing

#![no_std]
#![deny(missing_docs)]

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "sgx")] {
        extern crate mc_sgx_alloc;
        pub use mc_sgx_panic as panic;

        // Compat with std
        mod thread {
            pub use mc_sgx_panic::thread_panicking as panicking;
        }

        pub use mc_sgx_sync as sync;
        pub use mc_sgx_debug::eprintln;

        pub use mc_sgx_service::{report, verify_report, calc_sealed_data_size, seal_data, get_sealed_payload_sizes, unseal_data};
    }
    else {
        extern crate std;
        mod thread {
            pub use std::thread::panicking;
        }
        pub use std::panic;
        pub use std::sync;
        pub use std::eprintln;

        mod mock_service;
        pub use mock_service::{report, verify_report, calc_sealed_data_size, seal_data, get_sealed_payload_sizes, unseal_data};
    }
}
