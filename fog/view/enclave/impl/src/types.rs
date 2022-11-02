// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Helper structs for client `QueryResponse` collation.

use alloc::vec::Vec;
use mc_common::HashSet;
use mc_fog_types::{
    common::BlockRange,
    view::{DecommissionedIngestInvocation, QueryResponse, RngRecord},
};

/// Helper struct that contains the decrypted `QueryResponse` and the
/// `BlockRange` the shard is responsible for.
#[derive(Clone)]
pub(crate) struct DecryptedMultiViewStoreQueryResponse {
    /// Decrypted `QueryResponse`
    pub(crate) query_response: QueryResponse,
    /// The `BlockRange` that the shard is meant to process.
    pub(crate) block_range: BlockRange,
}

/// Helper struct that contains block data for the client `QueryResponse`
#[derive(Clone)]
pub(crate) struct BlockData {
    /// The highest processed block count that will be returned to the client.
    pub(crate) highest_processed_block_count: u64,
    /// The timestamp for the highest processed block count
    pub(crate) highest_processed_block_signature_timestamp: u64,
}

/// Helper struct that contains data associated with the "last known" fields in
/// the `QueryResponse`.
#[derive(Default)]
pub(crate) struct LastKnownData {
    /// The globally maximum block count that any store has seen but not
    /// necessarily processed.
    pub(crate) last_known_block_count: u64,
    /// The cumulative TxOut count associated with the last known block count.
    pub(crate) last_known_block_cumulative_txo_count: u64,
}

/// Helper struct that contains `QueryResponse` fields that should be shared
/// across all shards, but might not be do to distributed system latencies.
pub(crate) struct CommonShardData {
    /// Blocks that Fog Ingest was unable to process.
    pub(crate) missed_block_ranges: Vec<BlockRange>,
    /// All RNG records for a given user.
    pub(crate) rng_records: Vec<RngRecord>,
    /// Any records of decommissioned ingest invocations, which implies that an
    /// RNG will no longer be used.
    pub(crate) decommissioned_ingest_invocations: Vec<DecommissionedIngestInvocation>,
    /// The index of the next user id event that the user should query.
    pub(crate) next_start_from_user_event_id: i64,
}

impl BlockData {
    pub(crate) fn new(
        highest_processed_block_count: u64,
        highest_processed_block_signature_timestamp: u64,
    ) -> Self {
        Self {
            highest_processed_block_count,
            highest_processed_block_signature_timestamp,
        }
    }
}
impl Default for BlockData {
    fn default() -> Self {
        Self {
            highest_processed_block_count: u64::MIN,
            highest_processed_block_signature_timestamp: u64::MIN,
        }
    }
}

impl LastKnownData {
    pub(crate) fn new(
        last_known_block_count: u64,
        last_known_block_cumulative_txo_count: u64,
    ) -> Self {
        Self {
            last_known_block_count,
            last_known_block_cumulative_txo_count,
        }
    }
}

impl CommonShardData {
    pub(crate) fn new(
        missed_block_ranges: Vec<BlockRange>,
        rng_records: Vec<RngRecord>,
        decommissioned_ingest_invocations: Vec<DecommissionedIngestInvocation>,
        next_start_from_user_event_id: i64,
    ) -> Self {
        Self {
            missed_block_ranges,
            rng_records,
            decommissioned_ingest_invocations,
            next_start_from_user_event_id,
        }
    }
}

impl From<&[DecryptedMultiViewStoreQueryResponse]> for CommonShardData {
    fn from(responses: &[DecryptedMultiViewStoreQueryResponse]) -> Self {
        let mut missed_block_ranges = HashSet::default();
        let mut rng_records = HashSet::default();
        let mut decommissioned_ingest_invocations = HashSet::default();
        let mut next_start_from_user_event_id = i64::MIN;

        for response in responses {
            missed_block_ranges.extend(response.query_response.missed_block_ranges.clone());
            rng_records.extend(response.query_response.rng_records.clone());
            decommissioned_ingest_invocations.extend(
                response
                    .query_response
                    .decommissioned_ingest_invocations
                    .clone(),
            );
            next_start_from_user_event_id = core::cmp::max(
                response.query_response.next_start_from_user_event_id,
                next_start_from_user_event_id,
            );
        }

        let missed_block_ranges = missed_block_ranges.into_iter().collect::<Vec<BlockRange>>();
        let rng_records = rng_records.into_iter().collect::<Vec<RngRecord>>();
        let decommissioned_ingest_invocations = decommissioned_ingest_invocations
            .into_iter()
            .collect::<Vec<DecommissionedIngestInvocation>>();

        CommonShardData::new(
            missed_block_ranges,
            rng_records,
            decommissioned_ingest_invocations,
            next_start_from_user_event_id,
        )
    }
}

#[cfg(test)]
mod shared_data_tests {
    extern crate std;
    use crate::{CommonShardData, DecryptedMultiViewStoreQueryResponse};
    use alloc::{vec, vec::Vec};
    use mc_fog_types::{
        common::BlockRange,
        view::{DecommissionedIngestInvocation, KexRngPubkey, QueryResponse, RngRecord},
    };
    use std::collections::HashSet;

    fn create_query_response(
        missed_block_ranges: Vec<BlockRange>,
        rng_records: Vec<RngRecord>,
        decommissioned_ingest_invocations: Vec<DecommissionedIngestInvocation>,
        next_start_from_user_event_id: i64,
    ) -> QueryResponse {
        QueryResponse {
            highest_processed_block_count: 0,
            highest_processed_block_signature_timestamp: 0,
            next_start_from_user_event_id,
            missed_block_ranges,
            rng_records,
            decommissioned_ingest_invocations,
            tx_out_search_results: vec![],
            last_known_block_count: 0,
            last_known_block_cumulative_txo_count: 0,
        }
    }

    #[test]
    fn responses_have_same_values() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        let missed_block_ranges = vec![
            BlockRange::new(0, 1),
            BlockRange::new(10, 12),
            BlockRange::new(33, 100),
            BlockRange::new(100, 200),
        ];

        let mut rng_records = Vec::with_capacity(STORE_COUNT);
        for i in 0..STORE_COUNT {
            let egress_public_key = KexRngPubkey {
                public_key: vec![i as u8; 32],
                version: i as u32,
            };
            let rng_record = RngRecord {
                ingest_invocation_id: i as i64,
                pubkey: egress_public_key,
                start_block: 0,
            };
            rng_records.push(rng_record);
        }

        let mut decommissioned_ingest_invocations = Vec::with_capacity(STORE_COUNT);
        for i in 0..STORE_COUNT {
            let decommissioned_ingest_invocation = DecommissionedIngestInvocation {
                ingest_invocation_id: i as i64,
                last_ingested_block: 10,
            };
            decommissioned_ingest_invocations.push(decommissioned_ingest_invocation);
        }

        const NEXT_START_FROM_USER_EVENT_ID: i64 = 100;

        for i in 0..STORE_COUNT {
            let query_response = create_query_response(
                missed_block_ranges.clone(),
                rng_records.clone(),
                decommissioned_ingest_invocations.clone(),
                NEXT_START_FROM_USER_EVENT_ID,
            );
            let block_range = BlockRange::new(i as u64, (i + 1) as u64);
            let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
                query_response,
                block_range,
            };
            decrypted_query_responses.push(decrypted_query_response);
        }

        let shared_data: CommonShardData = decrypted_query_responses.as_slice().into();

        let actual_missed_block_ranges =
            HashSet::<_>::from_iter(shared_data.missed_block_ranges.iter());
        let actual_rng_records = HashSet::<_>::from_iter(shared_data.rng_records.iter());
        let actual_decommissioned_ingest_invocations =
            HashSet::<_>::from_iter(shared_data.decommissioned_ingest_invocations.iter());

        let expected_missed_block_ranges = HashSet::<_>::from_iter(missed_block_ranges.iter());
        let expected_rng_records = HashSet::<_>::from_iter(rng_records.iter());
        let expected_decommissioned_ingest_invocations =
            HashSet::<_>::from_iter(decommissioned_ingest_invocations.iter());

        assert_eq!(actual_missed_block_ranges, expected_missed_block_ranges);
        assert_eq!(actual_rng_records, expected_rng_records);
        assert_eq!(
            actual_decommissioned_ingest_invocations,
            expected_decommissioned_ingest_invocations
        );
        assert_eq!(
            shared_data.next_start_from_user_event_id,
            NEXT_START_FROM_USER_EVENT_ID
        );
    }

    #[test]
    fn responses_have_different_values() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        let missed_block_ranges = vec![
            BlockRange::new(0, 1),
            BlockRange::new(10, 12),
            BlockRange::new(33, 100),
            BlockRange::new(100, 200),
        ];

        let mut rng_records = Vec::with_capacity(STORE_COUNT);
        for i in 0..STORE_COUNT {
            let egress_public_key = KexRngPubkey {
                public_key: vec![i as u8; 32],
                version: i as u32,
            };
            let rng_record = RngRecord {
                ingest_invocation_id: i as i64,
                pubkey: egress_public_key,
                start_block: 0,
            };
            rng_records.push(rng_record);
        }

        let mut decommissioned_ingest_invocations = Vec::with_capacity(STORE_COUNT);
        for i in 0..STORE_COUNT {
            let decommissioned_ingest_invocation = DecommissionedIngestInvocation {
                ingest_invocation_id: i as i64,
                last_ingested_block: 10,
            };
            decommissioned_ingest_invocations.push(decommissioned_ingest_invocation);
        }

        for i in 0..STORE_COUNT {
            let missed_block_ranges = vec![missed_block_ranges[i].clone()];
            let rng_records = vec![rng_records[i].clone()];
            let decommissioned_ingest_invocations =
                vec![decommissioned_ingest_invocations[i].clone()];

            let query_response = create_query_response(
                missed_block_ranges,
                rng_records,
                decommissioned_ingest_invocations,
                (i + 1) as i64,
            );
            let block_range = BlockRange::new(i as u64, (i + 1) as u64);
            let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
                query_response,
                block_range,
            };
            decrypted_query_responses.push(decrypted_query_response);
        }

        let shared_data: CommonShardData = decrypted_query_responses.as_slice().into();

        let actual_missed_block_ranges =
            HashSet::<_>::from_iter(shared_data.missed_block_ranges.iter());
        let actual_rng_records = HashSet::<_>::from_iter(shared_data.rng_records.iter());
        let actual_decommissioned_ingest_invocations =
            HashSet::<_>::from_iter(shared_data.decommissioned_ingest_invocations.iter());

        let expected_missed_block_ranges = HashSet::<_>::from_iter(missed_block_ranges.iter());
        let expected_rng_records = HashSet::<_>::from_iter(rng_records.iter());
        let expected_decommissioned_ingest_invocations =
            HashSet::<_>::from_iter(decommissioned_ingest_invocations.iter());

        assert_eq!(actual_missed_block_ranges, expected_missed_block_ranges);
        assert_eq!(actual_rng_records, expected_rng_records);
        assert_eq!(
            actual_decommissioned_ingest_invocations,
            expected_decommissioned_ingest_invocations
        );
        assert_eq!(
            shared_data.next_start_from_user_event_id,
            STORE_COUNT as i64
        );
    }
}
