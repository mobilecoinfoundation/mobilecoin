// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_fog_recovery_db_iface::{FogUserEvent, RecoveryDb};
use mc_fog_types::view::QueryResponse;
use mc_fog_view_protocol::FogViewConnection;

// A structure that wraps recovery db reader and implements FogViewConnection,
// bypassing view node grpc and view enclave entirely.
// This is useful for integration tests.
// This allows to validate acct_crypto::polling module against fog ingest
// directly.
pub struct PassThroughViewClient<R: RecoveryDb> {
    db: R,
}

impl<R: RecoveryDb> PassThroughViewClient<R> {
    pub fn new(db: R) -> Self {
        Self { db }
    }
}

impl<R: RecoveryDb> FogViewConnection for PassThroughViewClient<R> {
    type Error = R::Error;

    fn request(
        &mut self,
        start_from_user_event_id: i64,
        start_from_block_index: u64,
        search_keys: Vec<Vec<u8>>,
    ) -> Result<QueryResponse, Self::Error> {
        let (user_events, next_start_from_user_event_id) =
            self.db.search_user_events(start_from_user_event_id)?;

        let highest_known_block_count = self
            .db
            .get_highest_known_block_index()?
            .map(|v| v + 1)
            .unwrap_or(0);
        let cumulative_txo_count = if highest_known_block_count > 0 {
            self.db
                .get_cumulative_txo_count_for_block(highest_known_block_count - 1)?
                .unwrap_or(0)
        } else {
            0
        };

        // Prepare the untrusted part of the response - duplicated from the view enclave
        // code.
        let mut missed_block_ranges = Vec::new();
        let mut rng_records = Vec::new();
        let mut decommissioned_ingest_invocations = Vec::new();

        for event in user_events.into_iter() {
            match event {
                FogUserEvent::NewRngRecord(rng_record) => rng_records.push(rng_record),

                FogUserEvent::DecommissionIngestInvocation(decommissioned_ingest_invocation) => {
                    decommissioned_ingest_invocations.push(decommissioned_ingest_invocation)
                }

                FogUserEvent::MissingBlocks(range) => missed_block_ranges.push(range),
            }
        }

        let mut resp = QueryResponse {
            highest_processed_block_count: highest_known_block_count,
            highest_processed_block_signature_timestamp: 0,
            next_start_from_user_event_id,
            missed_block_ranges,
            rng_records,
            decommissioned_ingest_invocations,
            tx_out_search_results: Default::default(),
            last_known_block_count: highest_known_block_count,
            last_known_block_cumulative_txo_count: cumulative_txo_count,
        };

        resp.tx_out_search_results = self.db.get_tx_outs(start_from_block_index, &search_keys)?;

        Ok(resp)
    }
}
