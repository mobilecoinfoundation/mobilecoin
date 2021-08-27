// Copyright (c) 2018-2021 The MobileCoin Foundation

#![deny(missing_docs)]

//! Fog Report Connection handles connecting to the fog report service and
//! building up a FogReportResponses object needed to create a transaction
//! with fog recipients.

use displaydoc::Display;
use grpcio::{ChannelBuilder, Environment};
use mc_common::logger::{log, o, Logger};
use mc_fog_report_api::{report::ReportRequest, report_grpc};
use mc_fog_report_types::ReportResponse;
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::FogUri;
use std::sync::Arc;

pub use mc_fog_report_validation::FogReportResponses;

/// Fog report server connection based on grpcio
///
/// TODO: As an optimization, it might be good to make this object hold onto its
/// grpc channels, so that they can be reused across calls, instead of
/// establishing new connections each time.
#[derive(Clone)]
pub struct GrpcFogReportConnection {
    /// grpc environment
    env: Arc<Environment>,
    /// The logging instance
    logger: Logger,
}

impl GrpcFogReportConnection {
    /// Create a new GrpcFogReportConnection object
    pub fn new(env: Arc<Environment>, logger: Logger) -> Self {
        Self { env, logger }
    }

    /// Fetch fog reports corresponding to a series of FogUris, returning
    /// FogReportResponses table. This attempts to be efficient, not
    /// contacting a server twice if a FogUri appears twice.
    pub fn fetch_fog_reports(
        &self,
        uris: impl Iterator<Item = FogUri>,
    ) -> Result<FogReportResponses, Error> {
        let mut responses = FogReportResponses::default();
        self.fetch_fog_reports_if_not_cached(&mut responses, uris)?;
        Ok(responses)
    }

    /// Fetch fog reports, adding them to an existing cache, if they are not
    /// already cached. This can be used if e.g. the recipients are not all
    /// known at once, and the fetch operation needs to be called multiple
    /// times.
    pub fn fetch_fog_reports_if_not_cached(
        &self,
        responses: &mut FogReportResponses,
        uris: impl Iterator<Item = FogUri>,
    ) -> Result<(), Error> {
        for uri in uris {
            match responses.entry(uri.to_string()) {
                std::collections::btree_map::Entry::Occupied(_) => {}
                std::collections::btree_map::Entry::Vacant(ent) => {
                    ent.insert(self.fetch_fog_report(&uri)?);
                }
            }
        }
        Ok(())
    }

    /// Given a fog report uri, fetch its response over grpc, or return an
    /// error.
    pub fn fetch_fog_report(&self, uri: &FogUri) -> Result<ReportResponse, Error> {
        let logger = self.logger.new(o!("mc.fog.cxn" => uri.to_string()));

        // Build channel to this URI
        let ch =
            ChannelBuilder::default_channel_builder(self.env.clone()).connect_to_uri(uri, &logger);
        let report_grpc_client = report_grpc::ReportApiClient::new(ch);

        // Request reports
        let req = ReportRequest::new();
        let resp = report_grpc_client.get_reports(&req)?;

        if resp.reports.len() == 0 {
            log::warn!(
                self.logger,
                "Report server at {} has no available reports",
                uri
            );
            return Err(Error::NoReports(uri.clone()));
        }

        // Return PROST version of entire response
        Ok(resp.into())
    }
}

/// Errors that can occur during GrpcFogReportConnection operation
#[derive(Debug, Display)]
pub enum Error {
    /// grpc failure: {0}
    Rpc(grpcio::Error),
    /// Fog Report Server has no available reports: {0}
    NoReports(FogUri),
}

impl From<grpcio::Error> for Error {
    fn from(src: grpcio::Error) -> Self {
        Self::Rpc(src)
    }
}
