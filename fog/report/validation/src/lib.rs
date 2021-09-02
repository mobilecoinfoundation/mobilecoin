// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Logic for representing fog public keys from the fog-report server
//! that have been fully validated, and the associated metadata.
//!
//! Note: Ideally this crate would be no_std compatible, but that is
//! aspirational. The ReportResponse object is not no_std right now, and neither
//! is x509 stuff. This is tracked in FOG-334.
//! The main reason to make it no_std compatible is to support constructing
//! mobilecoin transactions with fog recipients on an embedded device like a
//! tiny hardware wallet, that doesn't have threads and won't have rust std.

#![deny(missing_docs)]

extern crate alloc;

mod traits;

/// Data structure for fog-ingest report validation
pub mod ingest_report;

#[cfg(feature = "automock")]
pub use crate::traits::MockFogPubkeyResolver;
pub use crate::traits::{FogPubkeyError, FogPubkeyResolver, FullyValidatedFogPubkey};

use crate::ingest_report::IngestReportVerifier;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
};
use core::str::FromStr;
use mc_account_keys::PublicAddress;
use mc_attest_core::Verifier;
use mc_fog_report_types::ReportResponse;
use mc_fog_sig::Verifier as FogSigVerifier;
use mc_util_uri::{FogUri, UriParseError};

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

/// A collection of unvalidated fog reports, together with an IAS verifier.
/// This object is passed to the TransactionBuilder object.
/// When fog is not involved, it can simply be defaulted.
///
/// Once constructed, this object can get validated fog pubkeys to build fog
/// hints for transactions, without talking to the internet, and so is
/// compatible with offline transactions to fog recipients. Only getting the
/// FogReportResponses requires an online connection.
#[derive(Default, Clone, Debug)]
pub struct FogResolver {
    responses: FogReportResponses,
    verifier: IngestReportVerifier,
}

impl FogResolver {
    /// Create a new FogResolver object, given serialized (unverified)
    /// fog report server responses,
    /// and an attestation verifier for fog ingest measurements.
    pub fn new(responses: FogReportResponses, verifier: &Verifier) -> Result<Self, UriParseError> {
        // Normalize URI strings
        let responses: FogReportResponses = responses
            .into_iter()
            .map(
                |(uri_str, resp)| -> Result<(String, ReportResponse), UriParseError> {
                    let uri = FogUri::from_str(&uri_str)?.to_string();
                    Ok((uri, resp))
                },
            )
            .collect::<Result<_, UriParseError>>()?;
        Ok(Self {
            responses,
            verifier: IngestReportVerifier::from(verifier),
        })
    }
}

impl FogPubkeyResolver for FogResolver {
    fn get_fog_pubkey(
        &self,
        recipient: &PublicAddress,
    ) -> Result<FullyValidatedFogPubkey, FogPubkeyError> {
        if let Some(url) = recipient.fog_report_url() {
            // Normalize the string to URL before lookup
            let url = FogUri::from_str(url)?.to_string();
            if let Some(result) = self.responses.get(&url) {
                // Verify the authority signature chain
                recipient.verify_fog_sig(result)?;
                // Get the report corresponding to our ID
                let report_id = recipient.fog_report_id().unwrap_or("").to_string();
                for report in result.reports.iter() {
                    if report_id == report.fog_report_id {
                        let pubkey = self
                            .verifier
                            .validate_ingest_ias_report(report.report.clone())?;
                        return Ok(FullyValidatedFogPubkey {
                            pubkey,
                            pubkey_expiry: report.pubkey_expiry,
                        });
                    }
                }
                Err(FogPubkeyError::NoMatchingReportId(url, report_id))
            } else {
                Err(FogPubkeyError::NoMatchingReportResponse(url))
            }
        } else {
            Err(FogPubkeyError::NoFogReportUrl)
        }
    }
}
