// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Logic for representing fog public keys from the fog-report server
//! that have been fully validated, and the associated metadata.
//!
//! Note: Ideally this crate would be no_std compatible, but that is
//! aspirational. The ReportResponse object is not no_std right now, and neither
//! is x509 stuff. This is tracked in FOG-334.
//! The main reason to make it no_std compatible is to support constructing
//! mobilecoin transactions with fog recipients on an embedded device like a
//! tiny hardware wallet, that doesn't have threads and won't have rust std.

extern crate alloc;

use core::fmt::{Debug, Display};
use displaydoc::Display;
use mc_account_keys::PublicAddress;
use mc_crypto_keys::RistrettoPublic;
use mc_fog_sig::Error as FogSigError;
use mc_util_uri::UriParseError;
#[cfg(feature = "automock")]
use mockall::*;
use std::collections::HashMap;

/// Class that can resolve a public address to a fully-validated fog public key
/// structure, including the pubkey expiry data from the report server.
#[cfg_attr(feature = "automock", automock)]
pub trait FogPubkeyResolver {
    /// Fetch and validate a fog public key, given a recipient's public address
    fn get_fog_pubkey(
        &self,
        recipient: &PublicAddress,
    ) -> Result<FullyValidatedFogPubkey, FogPubkeyError>;
}

/// Represents a fog public key validated to use for creating encrypted fog
/// hints. This object should be constructed only when the IAS report has been
/// validated, and the chain of trust from the connection has been validated,
/// and the the fog user's fog_authority_sig over the root subjectPublicKeyInfo
/// in the signature chain has been validated.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct FullyValidatedFogPubkey {
    /// The ristretto curve point which was extracted from the IAS report
    /// additional data after validation. This is the encryption key used to
    /// create encrypted fog hints. The corresponding private key lives only
    /// in SGX ingest nodes.
    pub pubkey: RistrettoPublic,
    /// The pubkey_expiry value is the latest block that fog-service promises
    /// that is valid to encrypt fog hints using this key for.
    /// The client should obey this limit by not setting tombstone block for a
    /// transaction larger than this limit if the fog pubkey is used.
    pub pubkey_expiry: u64,
}

/// An error that can occur when trying to get a validated fog pubkey from the
/// FogResolver object
/// TODO: Add x509 errors, user-sig check errors, etc. here
#[derive(Display, Debug)]
pub enum FogPubkeyError {
    /// No matching reports response for url = {0}
    NoMatchingReportResponse(String),
    /// No matching report id for url = {0}, report_id = {1}
    NoMatchingReportId(String, String),
    /// Address has no fog_report_url, cannot fetch fog pubkey
    NoFogReportUrl,
    /// Failed to parse fog url: {0}
    Url(UriParseError),
    /// Ingest report deserialization error: {0},
    Deserialization(mc_util_serial::decode::Error),
    /// Ingest report verification error: {0}
    IngestReport(String),
    /// Authority verification error: {0}
    Authority(String),
}

impl From<mc_util_serial::decode::Error> for FogPubkeyError {
    fn from(src: mc_util_serial::decode::Error) -> Self {
        Self::Deserialization(src)
    }
}

impl From<UriParseError> for FogPubkeyError {
    fn from(src: UriParseError) -> Self {
        Self::Url(src)
    }
}

impl<A: Debug + Display, R: Debug + Display> From<FogSigError<A, R>> for FogPubkeyError {
    fn from(src: FogSigError<A, R>) -> Self {
        FogPubkeyError::Authority(src.to_string())
    }
}

pub struct FogResolver(HashMap<PublicAddress, FullyValidatedFogPubkey>);

impl FogResolver {
    pub fn new(responses: HashMap<PublicAddress, FullyValidatedFogPubkey>) -> Self {
        FogResolver(responses)
    }
}

impl FogPubkeyResolver for FogResolver {
    fn get_fog_pubkey(
        &self,
        address: &PublicAddress,
    ) -> Result<FullyValidatedFogPubkey, FogPubkeyError> {
        self.0
            .get(address)
            .cloned()
            .ok_or(FogPubkeyError::NoFogReportUrl)
    }
}
