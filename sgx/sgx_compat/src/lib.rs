// Copyright (c) 2018-2020 MobileCoin Inc.

//! Compatibility layer for the use of sgx, meant to suport unit testing

#![no_std]
#![deny(missing_docs)]

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "sgx")] {
        extern crate sgx_alloc;
        pub use sgx_panic as panic;

        // Compat with std
        mod thread {
            pub use sgx_panic::thread_panicking as panicking;
        }

        pub use sgx_sync as sync;
        pub use sgx_debug::eprintln;

        pub use sgx_service::{report, verify_report, calc_sealed_data_size, seal_data, get_sealed_payload_sizes, unseal_data};
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
