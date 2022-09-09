// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Logic for representing fog public keys from the fog-report server
//! that have been fully validated, and the associated metadata.

#![deny(missing_docs)]

extern crate alloc;

use mc_fog_report_validation::{FogPubkeyError, FogPubkeyResolver, FullyValidatedFogPubkey};

use mc_fog_ingest_report::IngestReportVerifier;

use alloc::string::{String, ToString};
use core::str::FromStr;
use mc_account_keys::PublicAddress;
use mc_attest_verifier::Verifier;
use mc_fog_report_types::{FogReportResponses, ReportResponse};
use mc_fog_sig::Verifier as FogSigVerifier;
use mc_util_uri::{FogUri, UriParseError};
use serde::{Deserialize, Serialize};

/// A collection of unvalidated fog reports, together with an IAS verifier.
/// This object is passed to the TransactionBuilder object.
/// When fog is not involved, it can simply be defaulted.
///
/// Once constructed, this object can get validated fog pubkeys to build fog
/// hints for transactions, without talking to the internet, and so is
/// compatible with offline transactions to fog recipients. Only getting the
/// FogReportResponses requires an online connection.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
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
        let url = recipient
            .fog_report_url()
            .ok_or(FogPubkeyError::NoFogReportUrl)?;
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
                        .validate_ingest_ias_report(report.report.clone())
                        .map_err(|e| FogPubkeyError::IngestReport(e.to_string()))?;
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
    }
}
