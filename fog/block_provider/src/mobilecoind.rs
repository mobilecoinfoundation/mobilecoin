// Copyright (c) 2018-2023 The MobileCoin Foundation

use std::{sync::Arc, time::Duration};

use grpcio::{ChannelBuilder, EnvBuilder};
use mc_blockchain_types::{Block, BlockIndex};
use mc_common::logger::Logger;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_mobilecoind_api::{mobilecoind_api_grpc::MobilecoindApiClient, MobilecoindUri};
use mc_transaction_core::tx::{TxOut, TxOutMembershipProof};
use mc_util_grpc::ConnectionUriGrpcioChannel;

use crate::{BlockProvider, BlocksDataResponse, Error, TxOutInfoByPublicKeyResponse};

#[derive(Clone)]
pub struct MobilecoindBlockProvider {
    client: MobilecoindApiClient,
}

impl MobilecoindBlockProvider {
    pub fn new(mobilecoind_uri: &MobilecoindUri, logger: &Logger) -> Box<Self> {
        let env = Arc::new(EnvBuilder::new().name_prefix("Mobilecoind-GRPC").build());
        let ch = ChannelBuilder::new(env)
            .max_receive_message_len(std::i32::MAX)
            .max_send_message_len(std::i32::MAX)
            .connect_to_uri(mobilecoind_uri, logger);

        let client = MobilecoindApiClient::new(ch);

        Box::new(Self { client })
    }
}

impl BlockProvider for MobilecoindBlockProvider {
    fn num_blocks(&self) -> Result<u64, Error> {
        let response = self.client.get_ledger_info(&Default::default())?;
        Ok(response.block_count)
    }

    /// Get the latest block in the ledger.
    fn get_latest_block(&self) -> Result<Block, Error> {
        todo!()
    }

    /// Get block data of multiple blocks by block number, and in addition get
    /// information about the latest block. Also include block timestamp for
    /// each block, if available.
    fn get_blocks_data(&self, _block_indices: &[BlockIndex]) -> Result<BlocksDataResponse, Error> {
        todo!()
    }

    /// Poll indefinitely for a watcher timestamp, logging warnings if we wait
    /// for more than watcher_timeout.
    fn poll_block_timestamp(&self, _block_index: BlockIndex, _watcher_timeout: Duration) -> u64 {
        todo!()
    }

    /// Get TxOut and membership proof by tx out index.
    fn get_tx_out_and_membership_proof_by_index(
        &self,
        _tx_out_index: u64,
    ) -> Result<(TxOut, TxOutMembershipProof), Error> {
        todo!()
    }

    /// Get information about multiple TxOuts by their public keys, and in
    /// addition get information about the latest block.
    fn get_tx_out_info_by_public_key(
        &self,
        _tx_out_pub_keys: &[CompressedRistrettoPublic],
    ) -> Result<TxOutInfoByPublicKeyResponse, Error> {
        todo!()
    }
}
