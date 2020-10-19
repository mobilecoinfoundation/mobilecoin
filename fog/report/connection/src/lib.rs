// Copyright (c) 2018-2020 MobileCoin Inc.

//! Fog Report Connection handles resolving the public key from the report service
//! on making grpc to the reports endpoint

use core::str::FromStr;
use displaydoc::Display;
use grpcio::{ChannelBuilder, Environment};
use mc_account_keys::PublicAddress;
use mc_attest_core::{VerificationReport, Verifier};
use mc_common::logger::{log, o, Logger};
use mc_fog_api::report_grpc;
use mc_fog_report_validation::ingest_report::{Error as IngestReportError, IngestReportVerifier};
use mc_util_grpc::{auth::BasicCredentials, ConnectionUriGrpcioChannel};
use mc_util_uri::{ConnectionUri, FogUri, UriParseError};
use std::sync::Arc;

pub use mc_fog_report_validation::{FogPubkeyResolver, FullyValidatedFogPubkey};

#[derive(Debug, Display)]
pub enum Error {
    /// Recipient doesn't have fog
    RecipientHasNoFog,
    /// Invalid fog url: {0}
    InvalidFogUrl(UriParseError),
    /// grpc failure: {0}
    Rpc(grpcio::Error),
    /// deserialization failed: {0}
    DeserializationFailed(mc_util_serial::decode::Error),
    /// report rejected: {0}
    Rejected(IngestReportError),
    /// Fog Report Server has no available reports
    NoReports,
    /// Matching report not found
    NotFound,
}

impl From<UriParseError> for Error {
    fn from(src: UriParseError) -> Self {
        Self::InvalidFogUrl(src)
    }
}

impl From<grpcio::Error> for Error {
    fn from(src: grpcio::Error) -> Self {
        Self::Rpc(src)
    }
}

impl From<mc_util_serial::decode::Error> for Error {
    fn from(src: mc_util_serial::decode::Error) -> Self {
        Self::DeserializationFailed(src)
    }
}

impl From<IngestReportError> for Error {
    fn from(src: IngestReportError) -> Self {
        Self::Rejected(src)
    }
}

/// Fog Pubkey resolver based on grpcio
pub struct GrpcFogPubkeyResolver {
    /// Ingest report verifier
    verifier: IngestReportVerifier,
    /// The logging instance
    logger: Logger,
    /// grpc environment
    env: Arc<Environment>,
}

impl GrpcFogPubkeyResolver {
    pub fn new(verifier: &Verifier, env: Arc<Environment>, logger: Logger) -> Self {
        Self {
            verifier: IngestReportVerifier::from(verifier),
            env,
            logger,
        }
    }
}

impl FogPubkeyResolver for GrpcFogPubkeyResolver {
    type Error = Error;

    fn get_fog_pubkey(
        &mut self,
        recipient: &PublicAddress,
    ) -> Result<FullyValidatedFogPubkey, Error> {
        let fog_report_url_str = recipient.fog_report_url().ok_or(Error::RecipientHasNoFog)?;
        let fog_report_url = FogUri::from_str(fog_report_url_str)?;
        let fog_report_id_str = recipient.fog_report_id().unwrap_or("");

        let logger = self
            .logger
            .new(o!("mc.fog.cxn" => fog_report_url.to_string()));

        let creds = BasicCredentials::new(&fog_report_url.username(), &fog_report_url.password());

        // Build channel to this URI
        // FIXME: We must get the TLS fingerprints and do fingerprint checking with sig
        let ch = ChannelBuilder::default_channel_builder(self.env.clone())
            .connect_to_uri(&fog_report_url, &logger);
        let report_grpc_client = report_grpc::ReportApiClient::new(ch);

        // Request reports
        let req = mc_fog_api::report::ReportRequest::new();
        let resp = report_grpc_client.get_reports_opt(&req, creds.call_option()?)?;

        if resp.reports.len() == 0 {
            log::warn!(
                self.logger,
                "Report server at {} has no available reports",
                fog_report_url_str
            );
            return Err(Error::NoReports);
        }

        for rep in resp.reports.iter() {
            // Make sure the fog_url, which came from ingest --fqdn config param,
            // matches Alice's fog_url in her public identity
            // Note: Neither of these strings is expected to have scheme or port
            // So we should possibly load them as url's and normalize them by
            // removing those things before doing the test.
            log::debug!(
                logger,
                "Comparing found fog_report_id: '{}', with recipient fog_report_id: '{}'",
                rep.fog_report_id,
                fog_report_id_str,
            );
            if rep.fog_report_id == fog_report_id_str {
                // Get the pubkey from the attestation evidence
                // NOTE: We are not doing a key exchange, so we do not care about Ingest's ResponderId
                let remote_report: VerificationReport = mc_util_serial::deserialize(&rep.report)
                    .map_err(|err| {
                        log::error!(
                            logger,
                            "Failed deserializing fog ingest VerificationReport: report_id: '{}', err = {}",
                            fog_report_id_str,
                            err
                        );
                        err
                    })?;

                // Validate report
                let pubkey = self.verifier.validate_ingest_ias_report(remote_report).map_err(|err| {
                        log::error!(
                            logger,
                            "Failed validating fog ingest VerificationReport: report_id: '{}', err = {}",
                            fog_report_id_str,
                            err
                        );
                        err
                    })?;
                return Ok(FullyValidatedFogPubkey {
                    pubkey,
                    pubkey_expiry: rep.pubkey_expiry,
                    fog_report_id: rep.fog_report_id.clone(),
                });
            }
        }

        let found_urls: Vec<String> = resp
            .reports
            .iter()
            .map(|rep| format!("'{}'", rep.fog_report_id))
            .collect();
        log::error!(
            logger,
            "Could not find needed fog report among the returned reports: wanted id: '{}', found ids: [{}].",
            fog_report_id_str,
            found_urls.join(", ")
        );
        Err(Error::NotFound)
    }
}
