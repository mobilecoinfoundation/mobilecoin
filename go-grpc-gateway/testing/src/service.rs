use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_common::logger::{self, Logger};
use mc_fog_report_api::{
    report::{ReportRequest as ProtobufReportRequest, ReportResponse as ProtobufReportResponse},
    report_grpc::ReportApi,
};
use mc_fog_report_types::ReportResponse;
use mc_util_grpc::{check_request_chain_id, rpc_logger, send_result};
use mc_util_metrics::SVC_COUNTERS;

#[derive(Clone)]
pub struct Service {
    /// Network id stirng
    chain_id: String,
    /// Slog logger object
    logger: Logger,
}

impl Service {
    pub fn new(chain_id: String, logger: Logger) -> Self {
        Self { chain_id, logger }
    }

    fn build_report_response(&self) -> Result<ReportResponse, RpcStatus> {
        Ok(ReportResponse {
            reports: vec![],
            chain: vec![],
            signature: vec![0u8, 1u8, 0u8, 1u8],
        })
    }
}

// Implement grpc trait
impl ReportApi for Service {
    fn get_reports(
        &mut self,
        ctx: RpcContext,
        _request: ProtobufReportRequest,
        sink: UnarySink<ProtobufReportResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = check_request_chain_id(&self.chain_id, &ctx) {
                return send_result(ctx, sink, Err(err), logger);
            }

            // Build a prost response, then convert it to rpc/protobuf types
            send_result(
                ctx,
                sink,
                self.build_report_response()
                    .map(ProtobufReportResponse::from),
                logger,
            )
        })
    }
}
