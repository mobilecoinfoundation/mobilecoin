// Copyright (c) 2018-2020 MobileCoin Inc.

//! Intel SGX SDK EPID FFI Types

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::useless_transmute)]

use mc_sgx_core_types_sys::*;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
