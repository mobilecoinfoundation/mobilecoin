use grpcio::{RpcContext, Service, UnarySink};
use mc_common::logger::Logger;
use mc_mobilecoind_mirror::{
    mobilecoind_mirror_api::{PollRequest, PollResponse},
    mobilecoind_mirror_api_grpc::{create_mobilecoind_mirror, MobilecoindMirror},
};

#[derive(Clone)]
pub struct MirrorService {
    /// Logger.
    logger: Logger,
}

impl MirrorService {
    pub fn new(logger: Logger) -> Self {
        Self { logger }
    }

    pub fn into_service(self) -> Service {
        create_mobilecoind_mirror(self)
    }
}

impl MobilecoindMirror for MirrorService {
    fn poll(&mut self, _ctx: RpcContext, _request: PollRequest, _sink: UnarySink<PollResponse>) {
        todo!()
    }
}
