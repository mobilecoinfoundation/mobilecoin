// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Intel SGX SDK EPID FFI

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::useless_transmute)]

use mc_sgx_core_types_sys::*;
use mc_sgx_epid_types_sys::*;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
