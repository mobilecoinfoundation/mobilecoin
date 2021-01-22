// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This file contains the fake certificates and functions necessary to
//! simulate an IASv3 API service.

pub const IAS_SIM_ROOT_ANCHORS: &str =
    concat!(include_str!("../../data/sim/root_anchor.pem"), "\0");
pub const IAS_SIM_SIGNING_CHAIN: &str = concat!(include_str!("../../data/sim/chain.pem"), "\0");
pub const IAS_SIM_SIGNING_KEY: &str = concat!(include_str!("../../data/sim/signer.key"), "\0");
// hard-coded to match the contents of build.rs
pub const IAS_SIM_MODULUS: usize = 3072;
