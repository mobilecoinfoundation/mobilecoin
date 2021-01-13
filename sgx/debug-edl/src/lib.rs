// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Enclave EDL for the sgx_panic crate.

#![no_std]

/// The EDL definition, as a string
pub const SGX_DEBUG_EDL: &str = include_str!("sgx_debug.edl");

#[cfg(test)]
mod test {
    use super::SGX_DEBUG_EDL;

    #[test]
    fn edl_contents() {
        assert_eq!(SGX_DEBUG_EDL, include_str!("sgx_debug.edl"));
    }
}
