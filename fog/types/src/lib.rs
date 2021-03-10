// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]
#![deny(missing_docs)]

//! This crate provides prost versions of some types from fog report server
//! proto One reason that these prost versions are needed is so that
//! mc-fog-report-validation doesn't depend on grpcio, as `mc-fog-api` does.

extern crate alloc;

use alloc::{string::String, vec::Vec};
use mc_attest_core::VerificationReport;
use mc_crypto_digestible::Digestible;
use prost::Message;
use serde::{Deserialize, Serialize};

/// A fog report from the report server
#[derive(Clone, Digestible, Eq, PartialEq, Serialize, Deserialize, Message)]
pub struct Report {
    /// The fog_report_id of the report
    #[prost(string, tag = "1")]
    pub fog_report_id: String,
    /// The bytes of the verification report
    #[prost(message, required, tag = "2")]
    pub report: VerificationReport,
    /// The pubkey expiry value (a block index)
    #[prost(fixed64, tag = "3")]
    pub pubkey_expiry: u64,
}

/// An entire response from the report server
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Message)]
pub struct ReportResponse {
    /// A list of reports provided by the server.
    #[prost(message, repeated, tag = "1")]
    pub reports: Vec<Report>,
    /// A chain of DER-encoded X.509 Certificates, from root to leaf.
    ///
    /// The key type of the last certificate in the chain determines
    /// the correct parsing of the signature.
    #[prost(bytes, repeated, tag = "2")]
    pub chain: Vec<Vec<u8>>,
    /// A signature over the reports.
    #[prost(bytes, tag = "3")]
    pub signature: Vec<u8>,
}
