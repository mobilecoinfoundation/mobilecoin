// Copyright (c) 2018-2021 The MobileCoin Foundation

use super::Error;
use grpcio::{ChannelBuilder, Environment};
use mc_common::logger::Logger;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::{fog_common::BlockRange, ledger, ledger_grpc};
use mc_fog_uri::FogLedgerUri;
use mc_transaction_core::BlockIndex;
use mc_util_grpc::{BasicCredentials, ConnectionUriGrpcioChannel};
use mc_util_uri::ConnectionUri;
use std::{ops::Range, sync::Arc};

/// A non-attested connection to untrusted fog ledger endpoints
pub struct FogUntrustedLedgerGrpcClient {
    #[allow(unused)]
    uri: FogLedgerUri,
    blocks_client: ledger_grpc::FogBlockApiClient,
    tx_out_client: ledger_grpc::FogUntrustedTxOutApiClient,
    creds: BasicCredentials,
    #[allow(unused)]
    logger: Logger,
}

impl FogUntrustedLedgerGrpcClient {
    /// Create a new client object
    pub fn new(uri: FogLedgerUri, grpc_env: Arc<Environment>, logger: Logger) -> Self {
        let creds = BasicCredentials::new(&uri.username(), &uri.password());

        let ch = ChannelBuilder::default_channel_builder(grpc_env).connect_to_uri(&uri, &logger);

        let blocks_client = ledger_grpc::FogBlockApiClient::new(ch.clone());

        let tx_out_client = ledger_grpc::FogUntrustedTxOutApiClient::new(ch);

        Self {
            uri,
            blocks_client,
            tx_out_client,
            creds,
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
    ) -> Result<ledger::BlockResponse, Error> {
        let mut request = ledger::BlockRequest::new();
        for iter_range in block_ranges.into_iter() {
            request.ranges.push({
                let mut range = BlockRange::new();
                range.start_block = iter_range.start;
                range.end_block = iter_range.end;
                range
            });
        }
        let result = self
            .blocks_client
            .get_blocks_opt(&request, self.creds.call_option()?)?;
        Ok(result)
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
    ) -> Result<ledger::TxOutResponse, Error> {
        let mut request = ledger::TxOutRequest::new();
        for pubkey in tx_out_pubkeys.into_iter() {
            // Convert to external::CompressedRistretto
            request.tx_out_pubkeys.push((&pubkey).into());
        }

        let result = self
            .tx_out_client
            .get_tx_outs_opt(&request, self.creds.call_option()?)?;
        Ok(result)
    }
}
