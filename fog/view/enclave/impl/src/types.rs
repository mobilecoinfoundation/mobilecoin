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

impl From<&mut [DecryptedMultiViewStoreQueryResponse]> for BlockData {
    fn from(responses: &mut [DecryptedMultiViewStoreQueryResponse]) -> Self {
        responses.sort_unstable_by_key(|response| response.block_range.start_block);

        // Find the first time in which a highest processed block count does not equate
        // to the final block that the shard is responsible for.
        let mut result = BlockData::default();
        for response in responses.iter() {
            let response_highest_processed_block_count =
                response.query_response.highest_processed_block_count;
            if response_highest_processed_block_count > result.highest_processed_block_count {
                result = BlockData::new(
                    response_highest_processed_block_count,
                    response
                        .query_response
                        .highest_processed_block_signature_timestamp,
                );
            }

            // In this case, the shard hasn't processed all the blocks it's responsible for,
            // and, as such, those blocks might not be processed so we should return this
            // number.
            // TODO: Consider implementing logic that accounts for overlapping block ranges.
            //   If ranges overlap, then the next server might have processed those blocks
            //   that this shard did not process (but is responsible for).
            if response_highest_processed_block_count < response.block_range.end_block {
                return result;
            }
        }

        result
    }
}

impl From<&[DecryptedMultiViewStoreQueryResponse]> for LastKnownData {
    fn from(responses: &[DecryptedMultiViewStoreQueryResponse]) -> Self {
        responses
            .iter()
            .max_by_key(|response| response.query_response.last_known_block_count)
            .map_or_else(LastKnownData::default, |response| {
                LastKnownData::new(
                    response.query_response.last_known_block_count,
                    response
                        .query_response
                        .last_known_block_cumulative_txo_count,
                )
            })
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
mod last_known_data_tests {
    use crate::{DecryptedMultiViewStoreQueryResponse, LastKnownData};
    use alloc::{vec, vec::Vec};
    use mc_fog_types::{common::BlockRange, view::QueryResponse};

    fn create_query_response(
        last_known_block_count: u64,
        last_known_block_cumulative_txo_count: u64,
    ) -> QueryResponse {
        QueryResponse {
            highest_processed_block_count: 0,
            highest_processed_block_signature_timestamp: 0,
            next_start_from_user_event_id: 0,
            missed_block_ranges: vec![],
            rng_records: vec![],
            decommissioned_ingest_invocations: vec![],
            tx_out_search_results: vec![],
            last_known_block_count,
            last_known_block_cumulative_txo_count,
        }
    }

    #[test]
    fn different_last_known_block_counts() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        for i in 0..STORE_COUNT {
            let last_known_block_count = ((i + 1) * 10) as u64;
            let last_known_block_cumulative_txo_count = last_known_block_count * 2;
            let query_response = create_query_response(
                last_known_block_count,
                last_known_block_cumulative_txo_count,
            );
            let block_range = BlockRange::new(i as u64, last_known_block_count);
            let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
                query_response,
                block_range,
            };
            decrypted_query_responses.push(decrypted_query_response);
        }

        let last_response = decrypted_query_responses
            .last()
            .expect("Couldn't get last decrypted query response");
        let expected_last_known_block_count = last_response.query_response.last_known_block_count;
        let expected_last_known_block_cumulative_txo_count = last_response
            .query_response
            .last_known_block_cumulative_txo_count;

        let result = LastKnownData::from(decrypted_query_responses.as_slice());

        assert_eq!(
            result.last_known_block_count,
            expected_last_known_block_count
        );
        assert_eq!(
            result.last_known_block_cumulative_txo_count,
            expected_last_known_block_cumulative_txo_count
        );
    }

    #[test]
    fn same_last_known_block_counts() {
        const STORE_COUNT: usize = 4;
        const LAST_KNOWN_BLOCK_COUNT: u64 = 100;
        const LAST_KNOWN_BLOCK_CUMULATIVE_TXO_COUNT: u64 = 1000;

        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);
        for i in 0..STORE_COUNT {
            let end_block_count = ((i + 1) * 25) as u64;
            let query_response = create_query_response(
                LAST_KNOWN_BLOCK_COUNT,
                LAST_KNOWN_BLOCK_CUMULATIVE_TXO_COUNT,
            );
            let block_range = BlockRange::new(i as u64, end_block_count);
            let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
                query_response,
                block_range,
            };
            decrypted_query_responses.push(decrypted_query_response);
        }

        let result = LastKnownData::from(decrypted_query_responses.as_slice());

        assert_eq!(result.last_known_block_count, LAST_KNOWN_BLOCK_COUNT);
        assert_eq!(
            result.last_known_block_cumulative_txo_count,
            LAST_KNOWN_BLOCK_CUMULATIVE_TXO_COUNT
        );
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

#[cfg(test)]
mod get_block_data_tests {
    use crate::{BlockData, DecryptedMultiViewStoreQueryResponse};
    use alloc::{vec, vec::Vec};
    use mc_fog_types::{common::BlockRange, view::QueryResponse};

    fn create_query_response(
        highest_processed_block_count: u64,
        highest_processed_block_signature_timestamp: u64,
    ) -> QueryResponse {
        QueryResponse {
            highest_processed_block_count,
            highest_processed_block_signature_timestamp,
            next_start_from_user_event_id: 0,
            missed_block_ranges: vec![],
            rng_records: vec![],
            decommissioned_ingest_invocations: vec![],
            tx_out_search_results: vec![],
            last_known_block_count: highest_processed_block_count,
            last_known_block_cumulative_txo_count: 0,
        }
    }

    #[test]
    fn all_responses_fully_processed() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);
        for i in 0..STORE_COUNT {
            let query_response = create_query_response((i + 1) as u64, i as u64);
            let block_range = BlockRange::new(i as u64, (i + 1) as u64);
            let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
                query_response,
                block_range,
            };
            decrypted_query_responses.push(decrypted_query_response);
        }

        let result = BlockData::from(decrypted_query_responses.as_mut());

        let last_response = decrypted_query_responses.last().unwrap();
        assert_eq!(
            result.highest_processed_block_count,
            last_response.query_response.highest_processed_block_count
        );
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            last_response
                .query_response
                .highest_processed_block_signature_timestamp
        );
    }

    #[test]
    fn first_response_incomplete() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        // Make the first response "incomplete"- i.e. it hasn't processed all of its
        // blocks.
        let incomplete_query_response = create_query_response(2, 2);
        let block_range = BlockRange::new(0, 3);
        let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
            query_response: incomplete_query_response.clone(),
            block_range,
        };
        decrypted_query_responses.push(decrypted_query_response);

        // Make the second response fully processed.
        let query_response = create_query_response(6, 6);
        let block_range = BlockRange::new(3, 6);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the third response fully processed.
        let query_response = create_query_response(9, 9);
        let block_range = BlockRange::new(6, 9);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the fourth response fully processed.
        let query_response = create_query_response(12, 12);
        let block_range = BlockRange::new(9, 12);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        let result = BlockData::from(decrypted_query_responses.as_mut());

        assert_eq!(
            result.highest_processed_block_count,
            incomplete_query_response.highest_processed_block_count
        );
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            incomplete_query_response.highest_processed_block_signature_timestamp
        );
    }

    #[test]
    fn second_response_zero_processed_blocks() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        // Make the first response fully processed.
        let fully_processed_block_count = 3;
        let fully_processed_timestamp = 3;
        let query_response =
            create_query_response(fully_processed_block_count, fully_processed_timestamp);
        let block_range = BlockRange::new(0, 3);
        let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        };
        decrypted_query_responses.push(decrypted_query_response);

        // Make the second response process zero blocks.
        let query_response = create_query_response(0, 0);
        let block_range = BlockRange::new(3, 6);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the third response fully processed.
        let query_response = create_query_response(9, 9);
        let block_range = BlockRange::new(6, 9);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the fourth response incomplete.
        let query_response = create_query_response(10, 10);
        let block_range = BlockRange::new(9, 12);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        let result = BlockData::from(decrypted_query_responses.as_mut());

        assert_eq!(
            result.highest_processed_block_count,
            fully_processed_block_count
        );
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            fully_processed_timestamp
        );
    }

    #[test]
    fn second_response_incomplete() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        // Make the first response fully processed.
        let query_response = create_query_response(3, 3);
        let block_range = BlockRange::new(0, 3);
        let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        };
        decrypted_query_responses.push(decrypted_query_response);

        // Make the second response "incomplete"- i.e. it hasn't processed all of its
        // blocks.
        let incomplete_block_count = 4;
        let incomplete_timestamp = 4;
        let incomplete_query_response =
            create_query_response(incomplete_block_count, incomplete_block_count);
        let block_range = BlockRange::new(3, 6);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response: incomplete_query_response,
            block_range,
        });

        // Make the third response fully processed.
        let query_response = create_query_response(9, 9);
        let block_range = BlockRange::new(6, 9);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the fourth response incomplete.
        let query_response = create_query_response(10, 10);
        let block_range = BlockRange::new(9, 12);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        let result = BlockData::from(decrypted_query_responses.as_mut());

        assert_eq!(result.highest_processed_block_count, incomplete_block_count);
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            incomplete_timestamp
        );
    }

    #[test]
    fn penultimate_response_incomplete() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        // Make the first response fully processed.
        let query_response = create_query_response(3, 3);
        let block_range = BlockRange::new(0, 3);
        let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        };
        decrypted_query_responses.push(decrypted_query_response);

        // Make the second response fully processed.
        let incomplete_query_response = create_query_response(6, 6);
        let block_range = BlockRange::new(3, 6);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response: incomplete_query_response,
            block_range,
        });

        // Make the third response incomplete.
        let incomplete_block_count = 8;
        let incomplete_timestamp = 8;
        let query_response = create_query_response(incomplete_block_count, incomplete_timestamp);
        let block_range = BlockRange::new(6, 9);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the fourth response fully processed.
        let query_response = create_query_response(12, 12);
        let block_range = BlockRange::new(9, 12);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        let result = BlockData::from(decrypted_query_responses.as_mut());

        assert_eq!(result.highest_processed_block_count, incomplete_block_count);
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            incomplete_timestamp
        );
    }

    #[test]
    fn penultimate_response_zero_processed_blocks() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        // Make the first response fully processed.
        let query_response = create_query_response(1, 1);
        let block_range = BlockRange::new(0, 1);
        let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        };
        decrypted_query_responses.push(decrypted_query_response);

        // Make the second response fully processed.
        let second_response_highest_processed_block_count = 2;
        let second_response_timestamp = 2;
        let query_response = create_query_response(
            second_response_highest_processed_block_count,
            second_response_timestamp,
        );
        let block_range = BlockRange::new(1, 2);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the third response process zero blocks.
        let incomplete_query_response = create_query_response(0, 0);
        let block_range = BlockRange::new(2, 3);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response: incomplete_query_response,
            block_range,
        });

        // Make the fourth response fully processed.
        let query_response = create_query_response(4, 4);
        let block_range = BlockRange::new(3, 4);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        let result = BlockData::from(decrypted_query_responses.as_mut());

        assert_eq!(
            result.highest_processed_block_count,
            second_response_highest_processed_block_count,
        );
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            second_response_timestamp
        );
    }

    #[test]
    fn final_response_incomplete() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        // Make the first response fully processed.
        let query_response = create_query_response(3, 3);
        let block_range = BlockRange::new(0, 3);
        let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        };
        decrypted_query_responses.push(decrypted_query_response);

        // Make the second response fully processed.
        let incomplete_query_response = create_query_response(6, 6);
        let block_range = BlockRange::new(3, 6);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response: incomplete_query_response,
            block_range,
        });

        // Make the third response fully processed.
        let query_response = create_query_response(9, 9);
        let block_range = BlockRange::new(6, 9);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the fourth response incomplete.
        let incomplete_block_count = 10;
        let incomplete_timestamp = 10;
        let query_response = create_query_response(10, 10);
        let block_range = BlockRange::new(9, 12);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        let result = BlockData::from(decrypted_query_responses.as_mut());

        assert_eq!(result.highest_processed_block_count, incomplete_block_count);
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            incomplete_timestamp
        );
    }

    #[test]
    fn final_response_zero_processed_blocks() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        // Make the first response fully processed.
        let query_response = create_query_response(3, 3);
        let block_range = BlockRange::new(0, 3);
        let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        };
        decrypted_query_responses.push(decrypted_query_response);

        // Make the second response fully processed.
        let incomplete_query_response = create_query_response(6, 6);
        let block_range = BlockRange::new(3, 6);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response: incomplete_query_response,
            block_range,
        });

        // Make the third response fully processed.
        let last_fully_processed_block_count = 9;
        let last_fully_processed_timestamp = 9;
        let query_response = create_query_response(
            last_fully_processed_block_count,
            last_fully_processed_timestamp,
        );
        let block_range = BlockRange::new(6, 9);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the fourth response incomplete.
        let query_response = create_query_response(0, 0);
        let block_range = BlockRange::new(9, 12);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        let result = BlockData::from(decrypted_query_responses.as_mut());

        assert_eq!(
            result.highest_processed_block_count,
            last_fully_processed_block_count
        );
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            last_fully_processed_timestamp
        );
    }
}
