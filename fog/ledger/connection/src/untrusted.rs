// Copyright (c) 2018-2022 The MobileCoin Foundation

use super::Error;
use grpcio::{ChannelBuilder, Environment};
use mc_blockchain_types::BlockIndex;
use mc_common::{logger::Logger, trace_time};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::{fog_common::BlockRange, fog_ledger};
use mc_fog_uri::FogLedgerUri;
use mc_util_grpc::{BasicCredentials, ConnectionUriGrpcioChannel, GrpcRetryConfig};
use mc_util_uri::ConnectionUri;
use std::{ops::Range, sync::Arc};

/// A non-attested connection to untrusted fog ledger endpoints
pub struct FogUntrustedLedgerGrpcClient {
    uri: FogLedgerUri,
    blocks_client: fog_ledger::FogBlockApiClient,
    tx_out_client: fog_ledger::FogUntrustedTxOutApiClient,
    creds: BasicCredentials,
    grpc_retry_config: GrpcRetryConfig,
    #[allow(dead_code)]
    logger: Logger,
}

impl FogUntrustedLedgerGrpcClient {
    /// Create a new client object
    pub fn new(
        uri: FogLedgerUri,
        grpc_retry_config: GrpcRetryConfig,
        grpc_env: Arc<Environment>,
        logger: Logger,
    ) -> Self {
        let creds = BasicCredentials::new(&uri.username(), &uri.password());

        let ch = ChannelBuilder::default_channel_builder(grpc_env).connect_to_uri(&uri, &logger);

        let blocks_client = fog_ledger::FogBlockApiClient::new(ch.clone());

        let tx_out_client = fog_ledger::FogUntrustedTxOutApiClient::new(ch);

        Self {
            uri,
            blocks_client,
            tx_out_client,
            creds,
            grpc_retry_config,
            logger,
        }
    }

    /// Make (non-private) request to download missed blocks
    ///
    /// TODO: Make this marshall the protobuf-generated type into a nicer rust
    /// type?
    pub fn get_blocks<'a>(
        &self,
        block_ranges: impl IntoIterator<Item = &'a Range<BlockIndex>>,
    ) -> Result<fog_ledger::BlockResponse, Error> {
        trace_time!(self.logger, "FogUntrustedLedgerGrpcClient::get_blocks");

        let request = fog_ledger::BlockRequest {
            ranges: block_ranges
                .into_iter()
                .map(|range| BlockRange {
                    start_block: range.start,
                    end_block: range.end,
                })
                .collect(),
        };

        self.grpc_retry_config
            .retry(|| {
                self.blocks_client
                    .get_blocks_opt(&request, self.creds.call_option()?)
            })
            .map_err(|grpcio_error| Error::Grpc(self.uri.clone(), grpcio_error))
    }

    /// Make (non-private) request to check if particular TxOut public keys
    /// exist in the ledger. Note that these are guaranteed by consensus to
    /// be unique.
    ///
    /// TODO: Make this marshall the protobuf-generated type into a nicer rust
    /// type?
    pub fn get_tx_outs(
        &self,
        tx_out_pubkeys: impl IntoIterator<Item = CompressedRistrettoPublic>,
    ) -> Result<fog_ledger::TxOutResponse, Error> {
        trace_time!(self.logger, "FogUntrustedLedgerGrpcClient::get_tx_outs");

        let request = fog_ledger::TxOutRequest {
            tx_out_pubkeys: tx_out_pubkeys
                .into_iter()
                .map(|pubkey| (&pubkey).into())
                .collect(),
        };

        self.grpc_retry_config
            .retry(|| {
                self.tx_out_client
                    .get_tx_outs_opt(&request, self.creds.call_option()?)
            })
            .map_err(|grpcio_error| Error::Grpc(self.uri.clone(), grpcio_error))
    }
}
