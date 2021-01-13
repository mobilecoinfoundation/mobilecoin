// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Enclave EDL for sgx_slog crate.

#![no_std]

/// The EDL definition, as a string
pub const SGX_SLOG_EDL: &str = include_str!("sgx_slog.edl");

#[cfg(test)]
mod test {
    use super::SGX_SLOG_EDL;

    #[test]
    fn edl_contents() {
        assert_eq!(SGX_SLOG_EDL, include_str!("sgx_slog.edl"));
    }
}
