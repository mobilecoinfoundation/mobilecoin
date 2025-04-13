// Copyright (c) 2018-2022 The MobileCoin Foundation

use super::Error;
use grpcio::{ChannelBuilder, Environment};
use mc_common::{logger::Logger, trace_time};
use mc_fog_api::{fog_common::BlockRange, fog_ledger, fog_ledger::FogBlockApiClient};
use mc_fog_uri::{ConnectionUri, FogLedgerUri};
use mc_util_grpc::{BasicCredentials, ConnectionUriGrpcioChannel, GrpcRetryConfig};
use std::sync::Arc;

/// A unattested connection to the Fog Block service.
pub struct FogBlockGrpcClient {
    uri: FogLedgerUri,
    blocks_client: FogBlockApiClient,
    creds: BasicCredentials,
    grpc_retry_config: GrpcRetryConfig,
    logger: Logger,
}

impl FogBlockGrpcClient {
    /// Create a new client object
    pub fn new(
        uri: FogLedgerUri,
        grpc_retry_config: GrpcRetryConfig,
        grpc_env: Arc<Environment>,
        logger: Logger,
    ) -> Self {
        let creds = BasicCredentials::new(&uri.username(), &uri.password());

        let ch = ChannelBuilder::default_channel_builder(grpc_env).connect_to_uri(&uri, &logger);
        let blocks_client = FogBlockApiClient::new(ch);

        Self {
            uri,
            blocks_client,
            creds,
            grpc_retry_config,
            logger,
        }
    }

    /// Make a request to retrieve missed block ranges
    pub fn get_missed_block_ranges(
        &mut self,
        missed_block_ranges: Vec<BlockRange>,
    ) -> Result<fog_ledger::BlockResponse, Error> {
        trace_time!(self.logger, "FogBlockGrpcClient::get_missed_block_ranges");

        let request = fog_ledger::BlockRequest {
            ranges: missed_block_ranges,
        };

        self.grpc_retry_config
            .retry(|| {
                self.blocks_client
                    .get_blocks_opt(&request, self.creds.call_option()?)
            })
            .map_err(|grpcio_error| Error::Grpc(self.uri.clone(), grpcio_error))
    }
}
