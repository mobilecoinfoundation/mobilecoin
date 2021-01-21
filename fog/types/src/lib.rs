#![no_std]
#![deny(missing_docs)]

//! This crate provides prost versions of some types from fog report server proto
//! One reason that these prost versions are needed is so that mc-fog-report-validation
//! doesn't depend on grpcio, as `mc-fog-api` does.

extern crate alloc;

use alloc::{string::String, vec::Vec};
use prost::Message;
use serde::{Deserialize, Serialize};

/// A fog report from the report server
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Message)]
pub struct Report {
    /// The fog_report_id of the report
    #[prost(string, tag = "1")]
    pub fog_report_id: String,
    /// The bytes of the verification report
    #[prost(bytes, tag = "2")]
    pub report: Vec<u8>,
    /// The pubkey expiry value (a block index)
    #[prost(fixed64, tag = "3")]
    pub pubkey_expiry: u64,
}

/// An entire response from the report server
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Message)]
pub struct ReportResponse {
    /// The reports available from the server
    #[prost(message, repeated, tag = "1")]
    pub reports: Vec<Report>,
}
