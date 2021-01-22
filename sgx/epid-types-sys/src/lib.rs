// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Intel SGX SDK EPID FFI Types

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::useless_transmute)]

use mc_sgx_core_types_sys::{sgx_isv_svn_t, sgx_report_body_t};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
