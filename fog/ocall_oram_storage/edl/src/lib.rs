// Copyright (c) 2018-2021 MobileCoin Inc.

//! Enclave EDL for ocall_oram_storage crate.

#![no_std]

/// The EDL definition, as a string
pub const FOG_OCALL_ORAM_STORAGE_EDL: &str = include_str!("oram_storage.edl");

#[cfg(test)]
mod test {
    use super::FOG_OCALL_ORAM_STORAGE_EDL;

    #[test]
    fn edl_contents() {
        assert_eq!(FOG_OCALL_ORAM_STORAGE_EDL, include_str!("oram_storage.edl"));
    }
}
