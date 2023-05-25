// Copyright (c) 2018-2022 The MobileCoin Foundation

#![no_std]
#![deny(missing_docs)]

//! This crate provides prost versions of some types from fog report server
//! proto One reason that these prost versions are needed is so that
//! mc-fog-report-validation doesn't depend on grpcio, as `mc-fog-api` does.

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use mc_attest_core::VerificationReport;
use mc_crypto_digestible::Digestible;
use prost::Message;
use serde::{Deserialize, Serialize};

/// A fog report from the report server
#[derive(Clone, Digestible, Eq, PartialEq, Serialize, Deserialize, Message)]
pub struct Report {
    /// The fog_report_id of the report
    #[prost(string, tag = "1")]
    #[digestible(never_omit)]
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

/// Represents a set of unvalidated responses from Fog report servers
/// Key = Fog-url that was contacted, must match the string in user's public
/// address Value = The complete response from the fog report server
///
/// When constructing a transaction, the fog-url for each recipient should be
/// extracted from their public address, then a request to that report server
/// should be made. The responses should be collected in a map-structure (like
/// this). This should be done for each recipient.
///
/// This map structure is ultimately consumed by the TransactionBuilder object,
/// which validates the responses against the fog data in the public addresses
/// when building the transaction.
///
/// This map structure should not be cached, because the fog pubkeys have an
/// expiry date and don't live that long. They can be cached for a short time,
/// but the transaction builder enforces that the tombstone block for the
/// transaction is limited by the pubkey expiry value of any fog pubkey that is
/// used, so if these are cached too long, the transaction will be rejected by
/// consensus.
///
/// In the case of constructing off-line transactions with Fog recipients, the
/// flow is: (1) Take fog-urls from (offline) public addresses to the online
/// machine (2) Hit the fog report servers (online machine), producing
/// FogReportResponses (3) Take FogReportResponses to the offline machine, and
/// use with transaction builder,     to create the transaction offline.
/// (4) Take the constructed transaction to the online machine and submit to
/// consensus.
///
/// Note: there is no particular reason for this to be BTreeMap instead of
/// HashMap, except that it is slightly more portable, only requiring the alloc
/// crate.
pub type FogReportResponses = BTreeMap<String, ReportResponse>;
