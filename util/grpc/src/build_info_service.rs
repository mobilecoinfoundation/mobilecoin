// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Implementation of the BuildInfoApi service.

use crate::{
    build_info::{create_build_info_api, BuildInfo, BuildInfoApi},
    rpc_logger, send_result,
};
use grpcio::{RpcContext, Service, UnarySink};
use mc_common::logger::Logger;
use mc_util_metrics::SVC_COUNTERS;

/// A service that exposes the BuildInfo of a service recorded using
/// mc_util_build_info
#[derive(Clone)]
pub struct BuildInfoService {
    logger: Logger,
}

impl BuildInfoService {
    /// Create a new instance of the BuildInfo service
    pub fn new(logger: Logger) -> Self {
        Self { logger }
    }

    /// Convert into a grpcio::Service
    pub fn into_service(self) -> Service {
        create_build_info_api(self)
    }
}

/// Get the BuildInfo object, by reading from the BuildInfo crate
pub fn get_build_info() -> BuildInfo {
    use ::mc_util_build_info as bi;
    BuildInfo {
        git_commit: bi::git_commit().to_owned(),
        profile: bi::profile().to_owned(),
        debug: bi::debug().to_owned(),
        opt_level: bi::opt_level().to_owned(),
        debug_assertions: bi::debug_assertions().to_owned(),
        target_arch: bi::target_arch().to_owned(),
        target_feature: bi::target_feature().to_owned(),
        rustflags: bi::rustflags().to_owned(),
        sgx_mode: bi::sgx_mode().to_owned(),
        ias_mode: bi::ias_mode().to_owned(),
    }
}

impl BuildInfoApi for BuildInfoService {
    fn get_build_info(&mut self, ctx: RpcContext, _req: (), sink: UnarySink<BuildInfo>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        let logger = rpc_logger(&ctx, &self.logger);
        send_result(ctx, sink, Ok(get_build_info()), &logger);
    }
}
