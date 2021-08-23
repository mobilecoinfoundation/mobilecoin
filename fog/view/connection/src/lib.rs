// Copyright (c) 2018-2021 The MobileCoin Foundation

use fog_api::view_grpc;
use fog_enclave_connection::{EnclaveConnection, Error as EnclaveConnectionError};
use fog_uri::FogViewUri;
use fog_view_protocol::FogViewConnection;
use grpcio::{ChannelBuilder, Environment};
use mc_attest_core::Verifier;
use mc_common::{
    logger::{log, o, Logger},
    trace_time,
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use std::sync::Arc;

pub struct FogViewGrpcClient {
    conn: EnclaveConnection<FogViewUri, view_grpc::FogViewApiClient>,
    logger: Logger,
}

impl FogViewGrpcClient {
    pub fn new(uri: FogViewUri, verifier: Verifier, env: Arc<Environment>, logger: Logger) -> Self {
        let logger = logger.new(o!("mc.fog.cxn" => uri.to_string()));

        let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&uri, &logger);

        let grpc_client = view_grpc::FogViewApiClient::new(ch);

        Self {
            conn: EnclaveConnection::new(uri, grpc_client, verifier, logger.clone()),
            logger,
        }
    }
}

impl FogViewConnection for FogViewGrpcClient {
    type Error = EnclaveConnectionError;

    fn request(
        &mut self,
        start_from_user_event_id: i64,
        start_from_block_index: u64,
        search_keys: Vec<Vec<u8>>,
    ) -> Result<fog_types::view::QueryResponse, Self::Error> {
        trace_time!(self.logger, "FogViewGrpcClient::request");

        log::trace!(
            self.logger,
            "request: start_from_user_event_id={} start_from_block_index={} num_search_keys={}",
            start_from_user_event_id,
            start_from_block_index,
            search_keys.len()
        );

        let req = fog_types::view::QueryRequest {
            get_txos: search_keys,
        };

        let req_aad = fog_types::view::QueryRequestAAD {
            start_from_user_event_id,
            start_from_block_index,
        };

        let aad_bytes = mc_util_serial::encode(&req_aad);

        self.conn.encrypted_enclave_request(&req, &aad_bytes)
    }
}
