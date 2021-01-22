// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Intel SGX URTS FFI

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::useless_transmute)]

use mc_sgx_core_types_sys::{
    sgx_config_id_t, sgx_config_svn_t, sgx_enclave_id_t, sgx_misc_attribute_t, sgx_status_t,
    sgx_target_info_t,
};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
