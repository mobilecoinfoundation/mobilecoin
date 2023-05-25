// Copyright (c) 2018-2022 The MobileCoin Foundation

use std::sync::Arc;

use mc_blockchain_types::{BlockData, BlockMetadata, BlockMetadataContents, QuorumSet};
use mc_common::ResponderId;
use mc_crypto_keys::Ed25519Pair;
use mc_ledger_sync::BlockMetadataProvider;
use mc_sgx_report_cache_api::ReportableEnclave;

/// A [BlockMetadataProvider] that builds metadata from the configured quorum
/// set, enclave's AVR, and message signing key.
pub struct ConsensusMetadataProvider<E: ReportableEnclave> {
    responder_id: ResponderId,
    quorum_set: QuorumSet,
    enclave: E,
    msg_signer_key: Arc<Ed25519Pair>,
}

impl<E: ReportableEnclave> ConsensusMetadataProvider<E> {
    pub fn new(
        responder_id: ResponderId,
        quorum_set: QuorumSet,
        enclave: E,
        msg_signer_key: Arc<Ed25519Pair>,
    ) -> Self {
        Self {
            responder_id,
            quorum_set,
            enclave,
            msg_signer_key,
        }
    }
}

impl<E: ReportableEnclave> BlockMetadataProvider for ConsensusMetadataProvider<E> {
    fn get_metadata(&self, block_data: &BlockData) -> Option<BlockMetadata> {
        let verification_report = self.enclave.get_ias_report().expect("failed to get AVR");
        let contents = BlockMetadataContents::new(
            block_data.block().id.clone(),
            self.quorum_set.clone(),
            verification_report,
            self.responder_id.clone(),
        );
        Some(
            BlockMetadata::from_contents_and_keypair(contents, &self.msg_signer_key)
                .expect("failed to sign metadata"),
        )
    }
}
