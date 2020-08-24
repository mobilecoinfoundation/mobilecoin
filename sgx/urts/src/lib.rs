// Copyright (c) 2018-2020 MobileCoin Inc.

extern crate mc_common;
extern crate mc_sgx_libc_types;
extern crate mc_sgx_slog;
extern crate mc_sgx_types;

extern crate prost;

#[cfg(feature = "backtrace")]
extern crate rustc_demangle;
#[cfg(feature = "backtrace")]
#[macro_use]
extern crate lazy_static;

mod enclave;
mod eprintln;
mod panic;
mod slog;

#[cfg(feature = "backtrace")]
mod backtrace;

pub use enclave::*;
