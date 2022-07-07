// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Blockchain validators.

#![deny(missing_docs)]

pub mod error;
pub mod metadata_verifiers;
#[cfg(test)]
pub mod test_utils;

pub use crate::{
    error::{ParseError, VerificationError},
    metadata_verifiers::{
        avr::get_signing_key_from_verification_report_data, AvrHistoryConfig, AvrHistoryRecord,
        MetadataVerifier,
    },
};
