// Copyright (c) 2018-2020 MobileCoin Inc.

//! Enclave EDL for sgx_backtrace crate.

#![no_std]

/// The EDL definition, as a string
pub const SGX_BACKTRACE_EDL: &str = include_str!("sgx_backtrace.edl");

#[cfg(test)]
mod test {
    use super::SGX_BACKTRACE_EDL;

    #[test]
    fn edl_contents() {
        assert_eq!(SGX_BACKTRACE_EDL, include_str!("sgx_backtrace.edl"));
    }
}
