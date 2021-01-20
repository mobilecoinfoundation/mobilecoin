// Copyright (c) 2018-2020 MobileCoin Inc.

#![deny(missing_docs)]

//! Fog Report Connection handles connecting to the fog report service and
//! building up a FogReportResponses object needed to create a transaction
//! with fog recipients.

use displaydoc::Display;
use grpcio::{ChannelBuilder, Environment};
use mc_common::logger::{log, o, Logger};
use mc_fog_api::report_grpc;
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::FogUri;
use std::sync::Arc;

pub use mc_fog_report_validation::FogReportResponses;

/// Fog report server connection based on grpcio
///
/// TODO: As an optimization, it might be good to make this like a connection
/// pool that holds onto its grpc connections, so that they can be reused
/// if a client is constructing transactions frequently.
/// The user of this API would tear down this object when they want these
/// connections to be closed.
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

    /// Fetch fog reports corresponding to a series of FogUris.
    /// This attempts to be efficient, not contacting a server twice if a FogUri appears twice.
    pub fn fetch_fog_reports(
        &self,
        uris: impl Iterator<Item = FogUri>,
    ) -> Result<FogReportResponses, Error> {
        let mut responses = FogReportResponses::default();
        for uri in uris {
            self.fetch_fog_report(&mut responses, &uri)?;
        }
        Ok(responses)
    }

    /// Given a set of previously collected FogReportResponse's, and another Uri, make a corresponding
    /// request and add it to the collection, if such a response is not already present.
    pub fn fetch_fog_report(
        &self,
        responses: &mut FogReportResponses,
        uri: &FogUri,
    ) -> Result<(), Error> {
        match responses.entry(uri.to_string()) {
            std::collections::btree_map::Entry::Occupied(_) => Ok(()),
            std::collections::btree_map::Entry::Vacant(ent) => {
                let logger = self.logger.new(o!("mc.fog.cxn" => uri.to_string()));

                // Build channel to this URI
                let ch = ChannelBuilder::default_channel_builder(self.env.clone())
                    .connect_to_uri(uri, &logger);
                let report_grpc_client = report_grpc::ReportApiClient::new(ch);

                // Request reports
                let req = mc_fog_api::report::ReportRequest::new();
                let resp = report_grpc_client.get_reports(&req)?;

                if resp.reports.len() == 0 {
                    log::warn!(
                        self.logger,
                        "Report server at {} has no available reports",
                        uri
                    );
                    return Err(Error::NoReports);
                }

                // Store entire response, for later validation against measurement and public addresses
                ent.insert(resp);
                Ok(())
            }
        }
    }
}

/// Errors that can occur during GrpcFogReportConnection operation
#[derive(Debug, Display)]
pub enum Error {
    /// grpc failure: {0}
    Rpc(grpcio::Error),
    /// Fog Report Server has no available reports
    NoReports,
}

impl From<grpcio::Error> for Error {
    fn from(src: grpcio::Error) -> Self {
        Self::Rpc(src)
    }
}
