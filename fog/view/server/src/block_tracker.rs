// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_common::logger::{log, Logger};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_recovery_db_iface::IngressPublicKeyRecord;
use std::collections::HashMap;

/// A utility object that keeps track of which block number was processed for
/// every known ingress key. This provides utilities such as:
/// - Finding out what is the next block that needs processing for any of the
///   ingress keys.
/// - Finding out what is the highest block index we have encountered so far.
/// - Finding out for which block index have we processed data for all ingress
///   keys, while taking into account ingress keys reported lost
pub struct BlockTracker {
    processed_block_per_ingress_key: HashMap<CompressedRistrettoPublic, u64>,
    last_highest_processed_block_count: u64,
    logger: Logger,
}

impl BlockTracker {
    pub fn new(logger: Logger) -> Self {
        Self {
            processed_block_per_ingress_key: HashMap::default(),
            last_highest_processed_block_count: 0,
            logger,
        }
    }

    // Given a list of ingress keys and the current state, calculate which block
    // index needs to be processed next for each ingress key
    pub fn next_blocks(
        &self,
        ingress_key_records: &[IngressPublicKeyRecord],
    ) -> HashMap<CompressedRistrettoPublic, u64> {
        let mut next_blocks = HashMap::default();

        for rec in ingress_key_records {
            if let Some(last_processed_block) = self.processed_block_per_ingress_key.get(&rec.key) {
                // A block has previously been processed for this ingress key. See if the
                // next one can be provided by it, and if so add it to the list of next blocks
                // we would like to process.
                let next_block = last_processed_block + 1;
                if rec.covers_block_index(next_block) {
                    next_blocks.insert(rec.key, next_block);
                }
            } else {
                // No block has been processed for this ingress key, so the next block is the
                // first one, assuming it can actually be provided by the ingress key.
                // (It will not be able to provide the start block if it got lost
                // immediately after starting before scanning any blocks)
                if rec.covers_block_index(rec.status.start_block) {
                    next_blocks.insert(rec.key, rec.status.start_block);
                }
            }
        }

        next_blocks
    }

    /// Notify the tracker that a block has been processed (loaded into enclave
    /// and is now available)
    pub fn block_processed(&mut self, ingress_key: CompressedRistrettoPublic, block_index: u64) {
        if let Some(previous_block_index) = self
            .processed_block_per_ingress_key
            .insert(ingress_key, block_index)
        {
            // Sanity check that we are only moving forward and not skipping any blocks.
            assert!(block_index == previous_block_index + 1);
        }
    }

    /// Given a list of ingress keys, missing blocks and current state,
    /// calculate the highest processed block count number. The highest
    /// processed block count number is the block count for which we know we
    /// have loaded all required data, so the users can potentially compute
    /// their balance up to this block without missing any transactions.
    ///
    /// Arguments:
    /// * ingress_keys: IngressPublicKeyRecord's that exist in the database
    ///   right now. This indicates their start block, their last-scanned block,
    ///   their expiry block, and whether they are retired or lost. If the key
    ///   is marked lost, this may imply a missing block range, which affects
    ///   whether we can be blocked on that key for progress.
    /// * missing_block_ranges: Any manually entered missing block ranges.
    ///
    /// Returns:
    /// * The highest fully processed block count, which may be 0 if nothing is
    ///   processed
    /// * Optionally, an IngressPublicKeyRecord which is the *reason* that the
    ///   previous number is less than highest_known_block_index -- the next
    ///   thing we are waiting on for data.
    pub fn highest_fully_processed_block_count(
        &mut self,
        ingress_keys: &[IngressPublicKeyRecord],
    ) -> (u64, Option<IngressPublicKeyRecord>) {
        // The highest fully processed block count cannot exceed the highest known block
        // count
        let highest_known_block_count = self.highest_known_block_count();

        let initial_last_highest_processed_block_count = self.last_highest_processed_block_count;
        let mut reason_we_stopped: Option<IngressPublicKeyRecord> = None;

        // Each pass through the loop attempts to increase
        // self.last_highest_processed_block_count or break the loop and
        // indicate the reason we can't increase it
        'outer: loop {
            let next_block_index = self.last_highest_processed_block_count;
            let next_block_count = self.last_highest_processed_block_count + 1;

            log::trace!(
                self.logger,
                "checking if highest_processed_block_count can be advanced to {}",
                next_block_count,
            );

            // If the next block index we are checking doesn't exist yet, then we definitely
            // can't advance the highest processed block count.
            // This breaks the loop if ingress_keys set is empty.
            if highest_known_block_count < next_block_count {
                log::trace!(
                    self.logger,
                    "We processed everything up to highest known block count"
                );
                break 'outer;
            }

            // Go over all known ingress keys and check if
            // any of them need to provide this block and have not provided it
            for rec in ingress_keys {
                // If this ingress key isn't responsible to provide this block index, we can
                // move on
                if !rec.covers_block_index(next_block_index) {
                    continue;
                }

                // Check if the last block we actually loaded with this key is less than
                // next_block_index, if so then this is what we are stuck on
                if let Some(last_processed_block) =
                    self.processed_block_per_ingress_key.get(&rec.key)
                {
                    if next_block_index > *last_processed_block {
                        // This ingress key needs to provide this block, but we haven't got it yet
                        log::trace!(self.logger, "cannot advance highest_processed_block_count to {}, because ingress_key {:?} only processed block {}", next_block_count, rec.key, last_processed_block);
                        reason_we_stopped = Some(rec.clone());
                        break 'outer;
                    }
                } else {
                    // No blocks have been processed yet by this ingress key.
                    // If next_block_index < start_block then "covers_block_index" is false.
                    // So if we got here, next_block_index >= start_block, so we are blocked.
                    log::trace!(self.logger, "cannot advance highest_processed_block_count to {}, because ingress_key {:?} hasn't processed anything yet", next_block_count, rec.key);
                    reason_we_stopped = Some(rec.clone());
                    break 'outer;
                }
            }

            // If we got here it means there was no reason we cannot advance the highest
            // processed block count 1) next_block_index did not exceed
            // highest_known_block_index 2) next_block_index is not covered by
            // any ingress public key that has not provided it or been declared lost
            self.last_highest_processed_block_count = next_block_count;
        }

        if self.last_highest_processed_block_count != initial_last_highest_processed_block_count {
            log::info!(
                self.logger,
                "advancing last_highest_processed_block_count from {} to {}",
                initial_last_highest_processed_block_count,
                self.last_highest_processed_block_count,
            );
        }

        (self.last_highest_processed_block_count, reason_we_stopped)
    }

    /// Get the highest block count we have encountered.
    pub fn highest_known_block_count(&self) -> u64 {
        self.processed_block_per_ingress_key
            .iter()
            .map(|(_key, block_index)| *block_index + 1)
            .max()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_common::logger::test_with_logger;
    use mc_fog_recovery_db_iface::IngressPublicKeyStatus;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{cmp::min, iter::FromIterator};

    #[test_with_logger]
    fn next_blocks_empty(logger: Logger) {
        let block_tracker = BlockTracker::new(logger.clone());
        assert_eq!(block_tracker.next_blocks(&[]).len(), 0);
    }

    // Single key (hasn't scanned any blocks yet)
    #[test_with_logger]
    fn next_blocks_single_key_hasnt_scanned(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut block_tracker = BlockTracker::new(logger);
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 123,
                pubkey_expiry: 173,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };

        let expected_state = HashMap::from_iter(vec![(rec.key, rec.status.start_block)]);

        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Repeated call should result in the same expected result.
        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Advancing to the next block should advance the expected result.
        for i in 0..10 {
            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            let expected_state =
                HashMap::from_iter(vec![(rec.key, rec.status.start_block + i + 1)]);

            assert_eq!(
                block_tracker.next_blocks(&[rec.clone()]),
                expected_state,
                "i = {}",
                i
            );

            // Repeated call should result in the same expected result.
            assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);
        }
    }

    // Single ingestable range (commissioned, scanned some blocks)
    #[test_with_logger]
    fn next_blocks_single_range_commissioned_scanned_some(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut block_tracker = BlockTracker::new(logger);
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 123,
                pubkey_expiry: 173,
                retired: false,
                lost: false,
            },
            last_scanned_block: Some(126),
        };
        let expected_state = HashMap::from_iter(vec![(rec.key, rec.status.start_block)]);

        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Repeated call should result in the same expected result.
        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Advancing to the next block should advance the expected result.
        for i in 0..10 {
            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            let expected_state =
                HashMap::from_iter(vec![(rec.key, rec.status.start_block + i + 1)]);

            assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

            // Repeated call should result in the same expected result.
            assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);
        }
    }

    // Single key (retired, hasn't scanned anything)
    #[test_with_logger]
    fn next_blocks_single_key_retired_hasnt_scanned(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut block_tracker = BlockTracker::new(logger);

        let key = CompressedRistrettoPublic::from_random(&mut rng);
        let rec = IngressPublicKeyRecord {
            key,
            status: IngressPublicKeyStatus {
                start_block: 123,
                pubkey_expiry: 173,
                retired: true,
                lost: false,
            },
            last_scanned_block: None,
        };

        // This is the expected state because, even though the key is retired,
        // we promised to scan from 123 to 173. So the next thing we need is 123,
        // unless this key is declared lost
        let expected_state = HashMap::from_iter(vec![(key, 123)]);

        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Repeated call should result in the same expected result.
        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Advancing to the next block should return the same result.
        for i in 0..49 {
            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            let expected_state = HashMap::from_iter(vec![(key, 123 + i + 1)]);

            assert_eq!(
                block_tracker.next_blocks(&[rec.clone()]),
                expected_state,
                "i = {}",
                i
            );

            // Repeated call should result in the same expected result.
            assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);
        }
        block_tracker.block_processed(rec.key, rec.status.start_block + 49);

        // Now, we have scanned everything we have promised to scan, next blocks should
        // return empty.
        let expected_state = HashMap::from_iter(vec![]);
        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);
    }

    // Single ingestable range (decommissioned, scanned some blocks)
    #[test_with_logger]
    fn next_blocks_single_range_retired_scanned_some(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut block_tracker = BlockTracker::new(logger);
        let last_ingested_block = 126;
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 123,
                pubkey_expiry: 173,
                retired: true,
                lost: false,
            },
            last_scanned_block: Some(last_ingested_block),
        };

        let expected_state = HashMap::from_iter(vec![(rec.key, rec.status.start_block)]);

        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Repeated call should result in the same expected result.
        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Advancing to the next block should advance the expected result.
        for i in 0..10 {
            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            // Capped at the last block that was scanned.
            let expected_state =
                HashMap::from_iter(vec![(rec.key, rec.status.start_block + i + 1)]);

            assert_eq!(
                block_tracker.next_blocks(&[rec.clone()]),
                expected_state,
                "i = {}",
                i
            );

            // Repeated call should result in the same expected result.
            assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);
        }
    }

    // Single key (lost, hasn't scanned anything)
    #[test_with_logger]
    fn next_blocks_single_key_lost_hasnt_scanned(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let block_tracker = BlockTracker::new(logger);

        let key = CompressedRistrettoPublic::from_random(&mut rng);
        let rec = IngressPublicKeyRecord {
            key,
            status: IngressPublicKeyStatus {
                start_block: 123,
                pubkey_expiry: 173,
                retired: false,
                lost: true,
            },
            last_scanned_block: None,
        };

        // This is the expected state because, even though we promised to scan
        // some things, the key is now reported lost, so we only have to go up to
        // last-scanned block
        let expected_state = HashMap::from_iter(vec![]);

        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);
    }

    // Single key (lost, but scanned some blocks)
    #[test_with_logger]
    fn next_blocks_single_key_lost_scanned_some(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut block_tracker = BlockTracker::new(logger);

        let key = CompressedRistrettoPublic::from_random(&mut rng);
        let rec = IngressPublicKeyRecord {
            key,
            status: IngressPublicKeyStatus {
                start_block: 123,
                pubkey_expiry: 173,
                retired: false,
                lost: true,
            },
            last_scanned_block: Some(143),
        };

        // This is the expected state because, even though we lost the key,
        // the key did scan some things before it was lost, so now we have to go up to
        // last-sacnned block
        let expected_state = HashMap::from_iter(vec![(rec.key, rec.status.start_block)]);

        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);

        // Advancing to the next block should advance the expected result.
        for i in 0..20 {
            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            let expected_state =
                HashMap::from_iter(vec![(rec.key, rec.status.start_block + i + 1)]);

            assert_eq!(
                block_tracker.next_blocks(&[rec.clone()]),
                expected_state,
                "i = {}",
                i
            );

            // Repeated call should result in the same expected result.
            assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);
        }

        block_tracker.block_processed(rec.key, rec.status.start_block + 20);

        let expected_state = HashMap::from_iter(vec![]);
        assert_eq!(block_tracker.next_blocks(&[rec.clone()]), expected_state);
    }

    // Two ingestable ranges should advance independently of eachother
    #[test_with_logger]
    fn next_blocks_multiple_keys(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut block_tracker = BlockTracker::new(logger);
        let rec1 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 123,
                pubkey_expiry: 200,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };
        let rec2 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 3000,
                pubkey_expiry: 200,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };

        let expected_state = HashMap::from_iter(vec![(rec1.key, rec1.status.start_block)]);

        assert_eq!(block_tracker.next_blocks(&[rec1.clone()]), expected_state);

        // Repeated call should result in the same expected result.
        assert_eq!(block_tracker.next_blocks(&[rec1.clone()]), expected_state);

        // Try again with the second ingestable range.
        let expected_state = HashMap::from_iter(vec![(rec2.key, rec2.status.start_block)]);

        assert_eq!(block_tracker.next_blocks(&[rec2.clone()]), expected_state);

        // Advancing the first one should not affect the second.
        block_tracker.block_processed(rec1.key, rec1.status.start_block);

        let expected_state = HashMap::from_iter(vec![(rec1.key, rec1.status.start_block + 1)]);

        assert_eq!(block_tracker.next_blocks(&[rec1.clone()]), expected_state);

        let expected_state = HashMap::from_iter(vec![(rec2.key, rec2.status.start_block)]);

        assert_eq!(block_tracker.next_blocks(&[rec2.clone()]), expected_state);

        // Try with both.
        let expected_state = HashMap::from_iter(vec![
            (rec1.key, rec1.status.start_block + 1),
            (rec2.key, rec2.status.start_block),
        ]);

        assert_eq!(
            block_tracker.next_blocks(&[rec1.clone(), rec2.clone()]),
            expected_state
        );
    }

    // highest_fully_processed_block_count behaves as expected
    #[test_with_logger]
    fn highest_fully_processed_block_count_all_empty(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        assert_eq!(
            block_tracker.highest_fully_processed_block_count(&[]),
            (0, None)
        );
    }

    // Check with a key that hasn't yet processed anything.
    #[test_with_logger]
    fn highest_fully_processed_block_missing_blocks_nothing_processed1(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 12,
                pubkey_expiry: 17,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };

        assert_eq!(
            block_tracker.highest_fully_processed_block_count(&[rec.clone()]),
            (0, None),
        );
    }

    // A block tracker with a single ingestable range tracks it properly as blocks
    // are processed when the start block is 0.
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_block_processed1(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 0,
                pubkey_expiry: 17,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };

        for i in 0..10 {
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec.clone()]),
                (rec.status.start_block + i, None)
            );

            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            // When there is only one key, we aren't considered blocked on it,
            // because the last thing it scanned is the highest thing we know of
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec.clone()]),
                (rec.status.start_block + i + 1, None)
            );
        }
    }

    // A block tracker with a single ingestable range makes progress appropriately
    // when the start block is greater than zero
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_block_processed2(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 10,
                pubkey_expiry: 17,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };

        assert_eq!(
            block_tracker.highest_fully_processed_block_count(&[rec.clone()]),
            (0, None)
        );

        for i in 0..10 {
            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            // When there is only one key, we aren't considered blocked on it,
            // because the last thing it scanned is the highest thing we know of
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec.clone()]),
                (rec.status.start_block + i + 1, None)
            );
        }
    }

    // A block tracker with a single ingestable range makes progress appropriately
    // when the start block is greater than zero, and some blocks are processed,
    // then the key is reported lost
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_block_processed3(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut rec = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 10,
                pubkey_expiry: 17,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };

        assert_eq!(
            block_tracker.highest_fully_processed_block_count(&[rec.clone()]),
            (0, None)
        );

        for i in 0..5 {
            block_tracker.block_processed(rec.key, rec.status.start_block + i);

            // When there is only one key, we aren't considered blocked on it,
            // because the last thing it scanned is the highest thing we know of
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec.clone()]),
                (rec.status.start_block + i + 1, None)
            );
        }

        rec.status.lost = true;

        // The highest processed block is still 15, but the reason we are blocked is now
        // None, and not the record, because the record was marked lost.
        assert_eq!(
            block_tracker.highest_fully_processed_block_count(&[rec.clone()]),
            (15, None)
        );
        // When the reason is None, that is supposed to mean that highest fully
        // processed = highest known.
        assert_eq!(block_tracker.highest_known_block_count(), 15);
    }

    // A block tracker with a multiple ingestable ranges waits for both of them.
    // When the slow one is marked lost, that unblocks progress.
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_multiple_recs(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut rec1 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 0,
                pubkey_expiry: 17,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };
        let rec2 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 10,
                pubkey_expiry: 17,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };

        // Initially, we're at 0.
        assert_eq!(
            block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
            (0, None)
        );

        // Advancing the first ingestable range would only get us up to 10 since at that
        // point we also need the 2nd range to advance.
        for i in 0..10 {
            block_tracker.block_processed(rec1.key, i);

            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
                (min(rec2.status.start_block, i + 1), None)
            );
        }

        // At this point, the reason we are blocked is rec2
        for i in 10..20 {
            block_tracker.block_processed(rec1.key, i);

            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
                (min(rec2.status.start_block, i + 1), Some(rec2.clone()))
            );
        }

        // Advancing the second range would get us all the way to the first one and stop
        // there.
        for i in 0..10 {
            block_tracker.block_processed(rec2.key, rec2.status.start_block + i);

            // Note: We advanced rec1 20 times in previous loop
            // The reason we are blocked changes once we reach block 20, because then
            // neither record is slower
            let expected = if i == 9 {
                (20, None)
            } else {
                (rec2.status.start_block + i + 1, Some(rec2.clone()))
            };
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
                expected,
                "i = {}",
                i
            );
        }

        // After this point, rec1 is the slow one, so that is the reason we are blocked
        for i in 10..30 {
            block_tracker.block_processed(rec2.key, rec2.status.start_block + i);

            let expected = (20, Some(rec1.clone()));
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
                expected,
                "i = {}",
                i
            );
        }

        // Test that marking rec1 lost enables us to progress all the way to rec2
        rec1.status.lost = true;
        let expected = (40, None);
        assert_eq!(
            block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
            expected,
        );
    }

    // A block tracker with multiple ingress keys waits for both of them,
    // and if a key is reported lost, it still blocks up until last-scanned for that
    // key is loaded
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_multiple_recs_some_lost2(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut rec1 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 0,
                pubkey_expiry: 27,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };
        let mut rec2 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 10,
                pubkey_expiry: 57,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };

        // Initially, we're at 0.
        assert_eq!(
            block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
            (0, None)
        );

        // Advancing the first ingestable range would only get us up to 10 since at that
        // point we also need the 2nd range to advance.
        for i in 0..10 {
            rec1.last_scanned_block = Some(i);
            block_tracker.block_processed(rec1.key, i);

            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
                (min(rec2.status.start_block, i + 1), None)
            );
        }

        // At this point, the reason we are blocked is rec2
        for i in 10..20 {
            rec1.last_scanned_block = Some(i);
            block_tracker.block_processed(rec1.key, i);

            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
                (min(rec2.status.start_block, i + 1), Some(rec2.clone()))
            );
        }

        // Advancing the second range would get us all the way to the first one and stop
        // there.
        for i in 10..20 {
            rec2.last_scanned_block = Some(i);
            block_tracker.block_processed(rec2.key, i);

            // Note: We advanced rec1 20 times in previous loop
            // The reason we are blocked changes once we reach block 20, because then
            // neither record is slower
            let expected = if i == 19 {
                (20, None)
            } else {
                (i + 1, Some(rec2.clone()))
            };
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
                expected,
                "i = {}",
                i
            );
        }

        // After this point, rec1 is the slow one, so that is the reason we are blocked
        for i in 20..40 {
            block_tracker.block_processed(rec2.key, i);

            let expected = (20, Some(rec1.clone()));
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
                expected,
                "i = {}",
                i
            );
        }

        // Test that marking rec1 lost still blocks us until we have processed up to
        // last scanned block of rec1
        rec1.last_scanned_block = Some(26);
        rec1.status.lost = true;

        for i in 20..27 {
            let expected = (i, Some(rec1.clone()));
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
                expected,
            );

            block_tracker.block_processed(rec1.key, i);
        }

        // Test that processing the remaining scanned blocks of rec1 allows us to make
        // progress all the way to rec2
        let expected = (40, None);
        assert_eq!(
            block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
            expected,
        );
    }

    /// A block tracker with a retired key, followed by a gap, followed by a new
    /// key, makes progress
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_retired_key_followed_by_gap(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut rec1 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 10,
                pubkey_expiry: 17,
                retired: true,
                lost: false,
            },
            last_scanned_block: None,
        };

        for i in 0..7 {
            let index = rec1.status.start_block + i;

            // Check that next blocks value matches what we expect
            let expected_state = HashMap::from_iter(vec![(rec1.key, index)]);

            assert_eq!(
                block_tracker.next_blocks(&[rec1.clone()]),
                expected_state,
                "i = {}",
                i
            );

            rec1.last_scanned_block = Some(index);
            block_tracker.block_processed(rec1.key, index);

            // Check that highest fully processed block count matches what we expect
            let expected = (index + 1, None);
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone()]),
                expected,
                "i = {}",
                i
            );
        }

        // Check that next blocks value matches what we expect
        let expected_state = HashMap::from_iter(vec![]);

        assert_eq!(block_tracker.next_blocks(&[rec1.clone()]), expected_state);

        // Check that highest fully processed block count matches what we expect
        let expected = (17, None);
        assert_eq!(
            block_tracker.highest_fully_processed_block_count(&[rec1.clone()]),
            expected
        );

        // Now add a new key that comes much later and check that we can make progress
        let mut rec2 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 30,
                pubkey_expiry: 47,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };

        for i in 0..7 {
            let index = rec2.status.start_block + i;

            // Check that next blocks value matches what we expect
            let expected_state = HashMap::from_iter(vec![(rec2.key, index)]);

            assert_eq!(
                block_tracker.next_blocks(&[rec1.clone(), rec2.clone()]),
                expected_state,
                "i = {}",
                i
            );

            // Make the block "exist" and "load" it
            rec2.last_scanned_block = Some(index);
            block_tracker.block_processed(rec2.key, index);

            // Check that highest fully processed block count matches what we expect
            let expected = (index + 1, None);
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
                expected,
                "i = {}",
                i
            );
        }
    }

    /// A block tracker with a retired key, which is concurrent with a new key,
    /// makes progress
    ///
    /// This is expected to correspond with how we do ingest enclave upgrades,
    /// when everything works.
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_retired_key_concurrent_with_active(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut rec1 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 10,
                pubkey_expiry: 22,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };

        for i in 0..7 {
            let index = rec1.status.start_block + i;

            // Check that next blocks value matches what we expect
            let expected_state = HashMap::from_iter(vec![(rec1.key, index)]);

            assert_eq!(
                block_tracker.next_blocks(&[rec1.clone()]),
                expected_state,
                "i = {}",
                i
            );

            rec1.last_scanned_block = Some(index);
            block_tracker.block_processed(rec1.key, index);

            // Check that highest fully processed block count matches what we expect
            let expected = (index + 1, None);
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone()]),
                expected,
                "i = {}",
                i
            );
        }

        // Now mark the key retired, and do 2 more blocks. Still 3 more until finished.
        rec1.status.retired = true;

        for i in 7..9 {
            let index = rec1.status.start_block + i;

            // Check that next blocks value matches what we expect
            let expected_state = HashMap::from_iter(vec![(rec1.key, index)]);

            assert_eq!(
                block_tracker.next_blocks(&[rec1.clone()]),
                expected_state,
                "i = {}",
                i
            );

            rec1.last_scanned_block = Some(index);
            block_tracker.block_processed(rec1.key, index);

            // Check that highest fully processed block count matches what we expect
            let expected = (index + 1, None);
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone()]),
                expected,
                "i = {}",
                i
            );
        }

        // Now add the second concurrent key
        let mut rec2 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 19,
                pubkey_expiry: 32,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };

        // Now add the next three blocks, after which rec1 should hit expiry
        for i in 9..12 {
            let index = rec1.status.start_block + i;

            // Check that next blocks value matches what we expect
            let expected_state = HashMap::from_iter(vec![(rec1.key, index), (rec2.key, index)]);

            assert_eq!(
                block_tracker.next_blocks(&[rec1.clone(), rec2.clone()]),
                expected_state,
                "i = {}",
                i
            );

            rec1.last_scanned_block = Some(index);
            rec2.last_scanned_block = Some(index);
            block_tracker.block_processed(rec1.key, index);
            block_tracker.block_processed(rec2.key, index);

            // Check that highest fully processed block count matches what we expect
            let expected = (index + 1, None);
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
                expected,
                "i = {}",
                i
            );
        }

        // Now add three more blocks. rec1 should be out of the picture now
        for i in 12..15 {
            let index = rec1.status.start_block + i;

            // Check that next blocks value matches what we expect
            let expected_state = HashMap::from_iter(vec![(rec2.key, index)]);

            assert_eq!(
                block_tracker.next_blocks(&[rec1.clone(), rec2.clone()]),
                expected_state,
                "i = {}",
                i
            );

            rec2.last_scanned_block = Some(index);
            block_tracker.block_processed(rec2.key, index);

            // Check that highest fully processed block count matches what we expect
            let expected = (index + 1, None);
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
                expected,
                "i = {}",
                i
            );
        }
    }

    /// A block tracker with a retired key, which is concurrent with a new key,
    /// which are then both lost, followed by a gap and a new key, makes
    /// progress.
    ///
    /// This is expected to correspond to, doing an ingest enclave upgrade, but
    /// then everything blows up and we have to restart the service later.
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_retired_key_concurrent_with_active_both_lost(
        logger: Logger,
    ) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut rec1 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 10,
                pubkey_expiry: 24,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };

        for i in 0..7 {
            let index = rec1.status.start_block + i;

            // Check that next blocks value matches what we expect
            let expected_state = HashMap::from_iter(vec![(rec1.key, index)]);

            assert_eq!(
                block_tracker.next_blocks(&[rec1.clone()]),
                expected_state,
                "i = {}",
                i
            );

            rec1.last_scanned_block = Some(index);
            block_tracker.block_processed(rec1.key, index);

            // Check that highest fully processed block count matches what we expect
            let expected = (index + 1, None);
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone()]),
                expected,
                "i = {}",
                i
            );
        }

        // Now mark the key retired, and do 2 more blocks. Still 5 more until finished.
        rec1.status.retired = true;

        for i in 7..9 {
            let index = rec1.status.start_block + i;

            // Check that next blocks value matches what we expect
            let expected_state = HashMap::from_iter(vec![(rec1.key, index)]);

            assert_eq!(
                block_tracker.next_blocks(&[rec1.clone()]),
                expected_state,
                "i = {}",
                i
            );

            rec1.last_scanned_block = Some(index);
            block_tracker.block_processed(rec1.key, index);

            // Check that highest fully processed block count matches what we expect
            let expected = (index + 1, None);
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone()]),
                expected,
                "i = {}",
                i
            );
        }

        // Now add the second concurrent key
        let mut rec2 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 19,
                pubkey_expiry: 32,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };

        // Now add the next three blocks. Still 2 more until first one finished
        for i in 9..12 {
            let index = rec1.status.start_block + i;

            // Check that next blocks value matches what we expect
            let expected_state = HashMap::from_iter(vec![(rec1.key, index), (rec2.key, index)]);

            assert_eq!(
                block_tracker.next_blocks(&[rec1.clone(), rec2.clone()]),
                expected_state,
                "i = {}",
                i
            );

            rec1.last_scanned_block = Some(index);
            rec2.last_scanned_block = Some(index);
            block_tracker.block_processed(rec1.key, index);
            block_tracker.block_processed(rec2.key, index);

            // Check that highest fully processed block count matches what we expect
            let expected = (index + 1, None);
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
                expected,
                "i = {}",
                i
            );
        }

        // Now mark both keys lost
        rec1.status.lost = true;
        rec2.status.lost = true;

        // Check that next blocks value and highest fully processed count matches what
        // we expect
        let expected_state = HashMap::from_iter(vec![]);

        assert_eq!(
            block_tracker.next_blocks(&[rec1.clone(), rec2.clone()]),
            expected_state,
        );
        assert_eq!(
            block_tracker.highest_fully_processed_block_count(&[rec1.clone(), rec2.clone()]),
            (22, None)
        );

        // Now add a third key much later, check that we can make progress with that key
        let mut rec3 = IngressPublicKeyRecord {
            key: CompressedRistrettoPublic::from_random(&mut rng),
            status: IngressPublicKeyStatus {
                start_block: 129,
                pubkey_expiry: 147,
                retired: false,
                lost: false,
            },
            last_scanned_block: None,
        };

        // Now add three more blocks at rec3. rec1 and rec2 should be out of the picture
        // now
        for i in 0..3 {
            let index = rec3.status.start_block + i;

            // Check that next blocks value matches what we expect
            let expected_state = HashMap::from_iter(vec![(rec3.key, index)]);

            assert_eq!(
                block_tracker.next_blocks(&[rec1.clone(), rec2.clone(), rec3.clone()]),
                expected_state,
                "i = {}",
                i
            );

            rec3.last_scanned_block = Some(index);
            block_tracker.block_processed(rec3.key, index);

            // Check that highest fully processed block count matches what we expect
            let expected = (index + 1, None);
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[
                    rec1.clone(),
                    rec2.clone(),
                    rec3.clone()
                ]),
                expected,
                "i = {}",
                i
            );
        }
    }

    // Highest known block count is 0 when there are no inputs.
    #[test_with_logger]
    fn highest_known_block_count_when_empty(logger: Logger) {
        let block_tracker = BlockTracker::new(logger);

        assert_eq!(block_tracker.highest_known_block_count(), 0);
    }

    // Highest known block count is set to the highest block count that was
    // processed.
    #[test_with_logger]
    fn highest_known_block_count_tracks_processed(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
        let mut block_tracker = BlockTracker::new(logger);

        block_tracker.block_processed(CompressedRistrettoPublic::from_random(&mut rng), 100);
        assert_eq!(block_tracker.highest_known_block_count(), 101);

        block_tracker.block_processed(CompressedRistrettoPublic::from_random(&mut rng), 80);
        assert_eq!(block_tracker.highest_known_block_count(), 101);

        block_tracker.block_processed(CompressedRistrettoPublic::from_random(&mut rng), 101);
        assert_eq!(block_tracker.highest_known_block_count(), 102);
    }
}
