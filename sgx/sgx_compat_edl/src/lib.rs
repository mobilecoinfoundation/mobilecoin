// Copyright (c) 2018-2020 MobileCoin Inc.

//! Library to write an "sgx_compat.edl" file which contains other enclave dependencies.

#![no_std]

pub const SGX_COMPAT_EDL: &str = include_str!("sgx_compat.edl");
