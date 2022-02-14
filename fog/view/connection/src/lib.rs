// Copyright (c) 2018-2021 The MobileCoin Foundation

use grpcio::{ChannelBuilder, Environment};
use mc_attest_verifier::Verifier;
use mc_common::{
    logger::{log, o, Logger},
    trace_time,
};
use mc_fog_api::view_grpc;
use mc_fog_enclave_connection::{EnclaveConnection, Error as EnclaveConnectionError};
use mc_fog_types::view::{QueryRequest, QueryRequestAAD, QueryResponse};
use mc_fog_uri::FogViewUri;
use mc_fog_view_protocol::FogViewConnection;
use mc_util_grpc::{ConnectionUriGrpcioChannel, GrpcRetryConfig};
use mc_util_telemetry::{tracer, Tracer};
use retry::{retry, Error as RetryError};
use std::{fmt::Display, sync::Arc};

pub struct FogViewGrpcClient {
    conn: EnclaveConnection<FogViewUri, view_grpc::FogViewApiClient>,
    grpc_retry_config: GrpcRetryConfig,
    uri: FogViewUri,
    logger: Logger,
}

impl FogViewGrpcClient {
    pub fn new(
        uri: FogViewUri,
        grpc_retry_config: GrpcRetryConfig,
        verifier: Verifier,
        env: Arc<Environment>,
        logger: Logger,
    ) -> Self {
        let logger = logger.new(o!("mc.fog.cxn" => uri.to_string()));

        let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&uri, &logger);

        let grpc_client = view_grpc::FogViewApiClient::new(ch);

        Self {
            conn: EnclaveConnection::new(uri.clone(), grpc_client, verifier, logger.clone()),
            grpc_retry_config,
            uri,
            logger,
        }
    }
}

impl FogViewConnection for FogViewGrpcClient {
    type Error = Error;

    fn request(
        &mut self,
        start_from_user_event_id: i64,
        start_from_block_index: u64,
        search_keys: Vec<Vec<u8>>,
    ) -> Result<QueryResponse, Self::Error> {
        tracer!().in_span("fog_view_grpc_request", |_cx_| {
            trace_time!(self.logger, "FogViewGrpcClient::request");

            log::trace!(
                self.logger,
                "request: start_from_user_event_id={} start_from_block_index={} num_search_keys={}",
                start_from_user_event_id,
                start_from_block_index,
                search_keys.len()
            );

            let req = QueryRequest {
                get_txos: search_keys,
            };

            let req_aad = QueryRequestAAD {
                start_from_user_event_id,
                start_from_block_index,
            };

            let aad_bytes = mc_util_serial::encode(&req_aad);

            retry(self.grpc_retry_config.get_retry_iterator(), || {
                self.conn
                    .retriable_encrypted_enclave_request(&req, &aad_bytes)
            })
            .map_err(|err| Error {
                uri: self.uri.clone(),
                error: err,
            })
        })
    }
}

#[derive(Debug)]
pub struct Error {
    pub uri: FogViewUri,
    pub error: RetryError<EnclaveConnectionError>,
}

impl Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            formatter,
            "Fog view connection error ({}): {}",
            &self.uri, &self.error
        )
    }
}
