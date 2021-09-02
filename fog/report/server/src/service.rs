// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Implementation of the ReportService

use crate::config::Materials;
use displaydoc::Display;
use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_common::logger::{self, log, Logger};
use mc_fog_api::{
    report::{ReportRequest as ProtobufReportRequest, ReportResponse as ProtobufReportResponse},
    report_grpc::ReportApi,
};
use mc_fog_recovery_db_iface::{RecoveryDbError, ReportDb};
use mc_fog_report_types::{Report, ReportResponse};
use mc_fog_sig_report::Signer as ReportSigner;
use mc_util_grpc::{rpc_database_err, rpc_internal_error, rpc_logger, send_result};
use mc_util_metrics::SVC_COUNTERS;
use prost::DecodeError;
use signature::{Error as SignatureError, Signature};

#[derive(Clone)]
pub struct Service<R: ReportDb + Clone + Send + Sync> {
    /// Access to the Report db is needed to retrieve the ingest report for
    /// clients.
    report_db: R,

    /// Cryptographic materials used in response construction
    materials: Materials,

    /// Slog logger object
    logger: Logger,
}

/// An internal error type used to marshal DB and signature errors
/// to RPC errors suitable for this service.
#[derive(Clone, Debug, Display, Eq, PartialEq)]
enum Error<E: RecoveryDbError> {
    /// There was an error contacting the database: {0}
    Db(E),
    /// The data in the database could not be decoded: {0}
    Decode(DecodeError),
    /// The signature could not be created
    Signature,
}

impl<E: RecoveryDbError> From<SignatureError> for Error<E> {
    fn from(_src: SignatureError) -> Error<E> {
        Error::Signature
    }
}

impl<E: RecoveryDbError> From<DecodeError> for Error<E> {
    fn from(src: DecodeError) -> Error<E> {
        Error::Decode(src)
    }
}

impl<E: RecoveryDbError> Error<E> {
    /// Convert the RPC Status
    fn into_rpc_status(self, logger: &Logger) -> RpcStatus {
        match self {
            Error::Db(db_err) => rpc_database_err(db_err, logger),
            Error::Decode(decode_err) => rpc_database_err(decode_err, logger),
            Error::Signature => rpc_internal_error("Signing process failed", self, logger),
        }
    }
}

impl<R: ReportDb + Clone + Send + Sync> Service<R> {
    /// Creates a new report service node (but does not create sockets and start
    /// it etc.)
    pub fn new(report_db: R, materials: Materials, logger: Logger) -> Self {
        Self {
            report_db,
            materials,
            logger,
        }
    }

    /// Loads report data from the database, signs it, and puts the results into
    /// constructs a new response structure.
    fn build_response(&self) -> Result<ReportResponse, Error<R::Error>> {
        mc_common::trace_time!(self.logger, "Building prost response from report DB");
        let reports = self
            .report_db
            .get_all_reports()
            .map_err(Error::Db)?
            .into_iter()
            .map(|(fog_report_id, report_data)| {
                Ok(Report {
                    fog_report_id,
                    report: report_data.report,
                    pubkey_expiry: report_data.pubkey_expiry,
                })
            })
            .collect::<Result<Vec<Report>, DecodeError>>()?;
        log::trace!(self.logger, "Got reports from DB, signing: {:?}", reports);
        let signature = self
            .materials
            .signing_keypair
            .sign_reports(&reports[..])?
            .as_bytes()
            .into();
        log::trace!(self.logger, "Reports list signature: {:?}", signature);
        Ok(ReportResponse {
            reports,
            chain: self.materials.chain.clone(),
            signature,
        })
    }
}

// Implement grpc trait
impl<R: ReportDb + Clone + Send + Sync> ReportApi for Service<R> {
    fn get_reports(
        &mut self,
        ctx: RpcContext,
        _request: ProtobufReportRequest,
        sink: UnarySink<ProtobufReportResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            // Build a prost response, then convert it to rpc/protobuf types and the errors
            // to rpc status codes.
            send_result(
                ctx,
                sink,
                self.build_response()
                    .map(ProtobufReportResponse::from)
                    .map_err(|e| e.into_rpc_status(logger)),
                &logger,
            )
        })
    }
}
