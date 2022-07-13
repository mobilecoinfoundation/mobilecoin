// Copyright (c) 2018-2022 The MobileCoin Foundation
//
// Contains helper methods that enable conversions for Fog Api types.

use crate::{fog_common, ingest_common, view::MultiViewStoreQueryRequest};
use mc_api::ConversionError;
use mc_attest_api::attest;
use mc_attest_enclave_api::{ClientSession, EnclaveMessage};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_types::common;

impl From<Vec<mc_attest_enclave_api::EnclaveMessage<mc_attest_enclave_api::ClientSession>>>
    for MultiViewStoreQueryRequest
{
    fn from(enclave_messages: Vec<EnclaveMessage<ClientSession>>) -> MultiViewStoreQueryRequest {
        enclave_messages
            .into_iter()
            .map(|enclave_message| enclave_message.into())
            .collect::<Vec<attest::Message>>()
            .into()
    }
}

impl From<Vec<attest::Message>> for MultiViewStoreQueryRequest {
    fn from(attested_query_messages: Vec<attest::Message>) -> MultiViewStoreQueryRequest {
        let mut multi_view_store_query_request = MultiViewStoreQueryRequest::new();
        multi_view_store_query_request.set_queries(attested_query_messages.into());

        multi_view_store_query_request
    }
}

impl From<&common::BlockRange> for fog_common::BlockRange {
    fn from(common_block_range: &common::BlockRange) -> fog_common::BlockRange {
        let mut proto_block_range = fog_common::BlockRange::new();
        proto_block_range.start_block = common_block_range.start_block;
        proto_block_range.end_block = common_block_range.end_block;

        proto_block_range
    }
}

impl TryFrom<&ingest_common::IngestSummary> for mc_fog_types::ingest_common::IngestSummary {
    type Error = ConversionError;
    fn try_from(proto_ingest_summary: &ingest_common::IngestSummary) -> Result<Self, Self::Error> {
        let ingest_controller_mode = match proto_ingest_summary.mode {
            ingest_common::IngestControllerMode::Idle => {
                mc_fog_types::ingest_common::IngestControllerMode::IDLE
            }
            ingest_common::IngestControllerMode::Active => {
                mc_fog_types::ingest_common::IngestControllerMode::ACTIVE
            }
        };
        let ingress_pubkey: CompressedRistrettoPublic =
            CompressedRistrettoPublic::try_from(proto_ingest_summary.get_ingress_pubkey())?;

        let result = mc_fog_types::ingest_common::IngestSummary {
            ingest_controller_mode,
            next_block_index: proto_ingest_summary.next_block_index,
            pubkey_expiry_window: proto_ingest_summary.pubkey_expiry_window,
            ingress_pubkey,
            egress_pubkey: proto_ingest_summary.get_egress_pubkey().to_vec(),
            kex_rng_version: proto_ingest_summary.kex_rng_version,
            peers: proto_ingest_summary.peers.to_vec(),
            ingest_invocation_id: proto_ingest_summary.ingest_invocation_id,
        };

        Ok(result)
    }
}
