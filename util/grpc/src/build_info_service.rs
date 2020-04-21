// Copyright (c) 2018-2020 MobileCoin Inc.

//! Implementation of the BuildInfoApi service.

use crate::{
    build_info::BuildInfoResponse,
    build_info_grpc::{create_build_info_api, BuildInfoApi},
    empty::Empty,
    rpc_logger, send_result,
};
use common::logger::Logger;
use grpcio::{RpcContext, Service, UnarySink};
use metrics::SVC_COUNTERS;

#[derive(Clone)]
pub struct BuildInfoService {
    logger: Logger,
}

impl BuildInfoService {
    pub fn new(logger: Logger) -> Self {
        Self { logger }
    }

    pub fn into_service(self) -> Service {
        create_build_info_api(self)
    }
}

impl BuildInfoApi for BuildInfoService {
    fn get_build_info(&mut self, ctx: RpcContext, _req: Empty, sink: UnarySink<BuildInfoResponse>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        let logger = rpc_logger(&ctx, &self.logger);

        let mut resp = BuildInfoResponse::new();
        resp.set_git_commit(::build_info::GIT_COMMIT.to_owned());
        resp.set_profile(::build_info::PROFILE.to_owned());
        resp.set_debug(::build_info::DEBUG.to_owned());
        resp.set_opt_level(::build_info::OPT_LEVEL.to_owned());
        resp.set_debug_assertions(::build_info::DEBUG_ASSERTIONS.to_owned());
        resp.set_target_arch(::build_info::TARGET_OS.to_owned());
        resp.set_target_feature(::build_info::TARGET_FEATURE.to_owned());
        resp.set_rustflags(::build_info::RUSTFLAGS.to_owned());
        resp.set_sgx_mode(::build_info::SGX_MODE.to_owned());
        resp.set_ias_mode(::build_info::IAS_MODE.to_owned());
        send_result(ctx, sink, Ok(resp), &logger);
    }
}
