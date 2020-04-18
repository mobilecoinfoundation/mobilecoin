// Copyright (c) 2018-2020 MobileCoin Inc.

#![feature(external_doc)]
#![doc(include = "../README.md")]
#![no_std]

use core::convert::TryFrom;
use mc_sgx_css::Signature;

pub fn sigstruct() -> Signature {
    Signature::try_from(&include_bytes!(env!("MCBUILD_ENCLAVE_CSS_PATH"))[..])
        .expect("Could not read measurement signature")
}
