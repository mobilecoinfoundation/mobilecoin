// Copyright (c) 2018-2022 The MobileCoin Foundation

//! See [verifier].

pub mod config;
pub mod verifier;

pub use self::{
    config::{AvrHistoryConfig, AvrHistoryRecord},
    verifier::{get_signing_key_from_verification_report_data, AvrVerificationRecord, AvrVerifier},
};
