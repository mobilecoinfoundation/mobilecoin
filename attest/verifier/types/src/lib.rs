// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Data structures for remote attestation.
#![no_std]
extern crate alloc;

// Prost generated versions
pub mod prost {
    use mc_crypto_digestible::Digestible;
    include!(concat!(env!("OUT_DIR"), "/external.rs"));
}

mod convert;
mod verification;

pub use crate::{
    convert::ConversionError,
    verification::{
        DcapEvidence, EnclaveReportDataContents, EvidenceMessage, VerificationReport,
        VerificationSignature,
    },
};
