// Copyright (c) 2018-2023 The MobileCoin Foundation

use grpcio::{RpcContext, RpcStatus, Service, UnarySink};
use light_client_api::{
    light_client::{VerifyTxORequest, VerifyTxOResponse},
    light_client_grpc::{create_light_client_verifier, LightClientVerifier},
};
use mc_common::logger::{scoped_global_logger, Logger};
use mc_util_grpc::{rpc_logger, send_result};

/// GRPC Verifier service
#[derive(Clone)]
pub struct VerifierService {
    /// Logger.
    #[allow(dead_code)]
    logger: Logger,
}

impl VerifierService {
    /// Create a new ClientService
    pub fn new(logger: Logger) -> Self {
        Self { logger }
    }

    /// Convert into a grpc service
    pub fn into_service(self) -> Service {
        create_light_client_verifier(self)
    }

    fn verify_impl(&self, _req: VerifyTxORequest) -> Result<VerifyTxOResponse, RpcStatus> {
        todo!()
    }
}

impl LightClientVerifier for VerifierService {
    fn verify(
        &mut self,
        ctx: RpcContext,
        req: VerifyTxORequest,
        sink: UnarySink<VerifyTxOResponse>,
    ) {
        // TODO let _timer = SVC_COUNTERS.req(&ctx);
        scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            // Build a prost response, then convert it to rpc/protobuf types and the errors
            // to rpc status codes.
            send_result(ctx, sink, self.verify_impl(req), logger)
        })
    }
}
