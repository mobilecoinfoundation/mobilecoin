// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Tests that a view store stops polling the recovery database once it has
//! loaded every block in its block range.

use chrono::NaiveDateTime;
use mc_common::{
    logger::{test_with_logger, Logger},
    time::SystemTimeProvider,
    ResponderId,
};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_kex_rng::KexRngPubkey;
use mc_fog_recovery_db_iface::{
    AddBlockDataStatus, Block, ExpiredInvocationRecord, FogUserEvent, IngestInvocationId,
    IngestableRange, IngressPublicKeyRecord, IngressPublicKeyRecordFilters, IngressPublicKeyStatus,
    RecoveryDb,
};
use mc_fog_sql_recovery_db::test_utils::SqlRecoveryDbTestContext;
use mc_fog_test_infra::{
    db_tests::{random_block, random_kex_rng_pubkey},
    get_enclave_path,
};
use mc_fog_types::{common::BlockRange, view::FixedTxOutSearchResult, ETxOutRecord};
use mc_fog_uri::FogViewStoreUri;
use mc_fog_view_enclave::SgxViewEnclave;
use mc_fog_view_server::{
    config::{MobileAcctViewConfig, ShardingStrategy::Epoch},
    server::ViewServer,
    sharding_strategy::EpochShardingStrategy,
};
use mc_util_from_random::FromRandom;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread::sleep,
    time::{Duration, Instant},
};

/// One past the last block the view store under test is responsible for.
const END_BLOCK: u64 = 5;

const DB_POLLING_INTERVAL: Duration = Duration::from_millis(100);

/// A `RecoveryDb` that counts every call made to it, so tests can tell
/// whether the view store is still polling.
#[derive(Clone)]
struct CountingRecoveryDb<DB: RecoveryDb> {
    inner: DB,
    num_calls: Arc<AtomicU64>,
    /// The highest `end_block` passed to `get_tx_outs_by_block_range_and_key`.
    max_requested_end_block: Arc<AtomicU64>,
}

impl<DB: RecoveryDb> CountingRecoveryDb<DB> {
    fn new(inner: DB) -> Self {
        Self {
            inner,
            num_calls: Default::default(),
            max_requested_end_block: Default::default(),
        }
    }

    fn num_calls(&self) -> u64 {
        self.num_calls.load(Ordering::SeqCst)
    }

    fn max_requested_end_block(&self) -> u64 {
        self.max_requested_end_block.load(Ordering::SeqCst)
    }

    /// The number of calls made to the database while sleeping for `duration`.
    fn num_calls_during(&self, duration: Duration) -> u64 {
        let before = self.num_calls();
        sleep(duration);
        self.num_calls() - before
    }

    fn record_call(&self) {
        self.num_calls.fetch_add(1, Ordering::SeqCst);
    }
}

impl<DB: RecoveryDb> RecoveryDb for CountingRecoveryDb<DB> {
    type Error = DB::Error;

    fn get_ingress_key_status(
        &self,
        key: &CompressedRistrettoPublic,
    ) -> Result<Option<IngressPublicKeyStatus>, Self::Error> {
        self.record_call();
        self.inner.get_ingress_key_status(key)
    }

    fn new_ingress_key(
        &self,
        key: &CompressedRistrettoPublic,
        start_block_count: u64,
    ) -> Result<u64, Self::Error> {
        self.record_call();
        self.inner.new_ingress_key(key, start_block_count)
    }

    fn retire_ingress_key(
        &self,
        key: &CompressedRistrettoPublic,
        set_retired: bool,
    ) -> Result<(), Self::Error> {
        self.record_call();
        self.inner.retire_ingress_key(key, set_retired)
    }

    fn get_last_scanned_block_index(
        &self,
        key: &CompressedRistrettoPublic,
    ) -> Result<Option<u64>, Self::Error> {
        self.record_call();
        self.inner.get_last_scanned_block_index(key)
    }

    fn get_ingress_key_records(
        &self,
        start_block_at_least: u64,
        ingress_public_key_record_filters: &IngressPublicKeyRecordFilters,
    ) -> Result<Vec<IngressPublicKeyRecord>, Self::Error> {
        self.record_call();
        self.inner
            .get_ingress_key_records(start_block_at_least, ingress_public_key_record_filters)
    }

    fn new_ingest_invocation(
        &self,
        prev_ingest_invocation_id: Option<IngestInvocationId>,
        ingress_public_key: &CompressedRistrettoPublic,
        egress_public_key: &KexRngPubkey,
        start_block: u64,
    ) -> Result<IngestInvocationId, Self::Error> {
        self.record_call();
        self.inner.new_ingest_invocation(
            prev_ingest_invocation_id,
            ingress_public_key,
            egress_public_key,
            start_block,
        )
    }

    fn get_ingestable_ranges(&self) -> Result<Vec<IngestableRange>, Self::Error> {
        self.record_call();
        self.inner.get_ingestable_ranges()
    }

    fn decommission_ingest_invocation(
        &self,
        ingest_invocation_id: &IngestInvocationId,
    ) -> Result<(), Self::Error> {
        self.record_call();
        self.inner
            .decommission_ingest_invocation(ingest_invocation_id)
    }

    fn add_block_data(
        &self,
        ingest_invocation_id: &IngestInvocationId,
        block: &Block,
        block_signature_timestamp: u64,
        txs: &[ETxOutRecord],
    ) -> Result<AddBlockDataStatus, Self::Error> {
        self.record_call();
        self.inner
            .add_block_data(ingest_invocation_id, block, block_signature_timestamp, txs)
    }

    fn report_lost_ingress_key(
        &self,
        lost_ingress_key: CompressedRistrettoPublic,
    ) -> Result<(), Self::Error> {
        self.record_call();
        self.inner.report_lost_ingress_key(lost_ingress_key)
    }

    fn get_missed_block_ranges(&self) -> Result<Vec<BlockRange>, Self::Error> {
        self.record_call();
        self.inner.get_missed_block_ranges()
    }

    fn search_user_events(
        &self,
        start_from_user_event_id: i64,
    ) -> Result<(Vec<FogUserEvent>, i64), Self::Error> {
        self.record_call();
        self.inner.search_user_events(start_from_user_event_id)
    }

    fn get_tx_outs(
        &self,
        start_block: u64,
        search_keys: &[Vec<u8>],
    ) -> Result<Vec<FixedTxOutSearchResult>, Self::Error> {
        self.record_call();
        self.inner.get_tx_outs(start_block, search_keys)
    }

    fn update_last_active_at(
        &self,
        ingest_invocation_id: &IngestInvocationId,
    ) -> Result<(), Self::Error> {
        self.record_call();
        self.inner.update_last_active_at(ingest_invocation_id)
    }

    fn get_tx_outs_by_block_and_key(
        &self,
        ingress_key: CompressedRistrettoPublic,
        block_index: u64,
    ) -> Result<Option<Vec<ETxOutRecord>>, Self::Error> {
        self.record_call();
        self.inner
            .get_tx_outs_by_block_and_key(ingress_key, block_index)
    }

    fn get_tx_outs_by_block_range_and_key(
        &self,
        ingress_key: CompressedRistrettoPublic,
        block_range: &BlockRange,
    ) -> Result<Vec<Vec<ETxOutRecord>>, Self::Error> {
        self.record_call();
        self.max_requested_end_block
            .fetch_max(block_range.end_block, Ordering::SeqCst);
        self.inner
            .get_tx_outs_by_block_range_and_key(ingress_key, block_range)
    }

    fn get_invocation_id_by_block_and_key(
        &self,
        ingress_key: CompressedRistrettoPublic,
        block_index: u64,
    ) -> Result<Option<IngestInvocationId>, Self::Error> {
        self.record_call();
        self.inner
            .get_invocation_id_by_block_and_key(ingress_key, block_index)
    }

    fn get_cumulative_txo_count_for_block(
        &self,
        block_index: u64,
    ) -> Result<Option<u64>, Self::Error> {
        self.record_call();
        self.inner.get_cumulative_txo_count_for_block(block_index)
    }

    fn get_block_signature_timestamp_for_block(
        &self,
        block_index: u64,
    ) -> Result<Option<u64>, Self::Error> {
        self.record_call();
        self.inner
            .get_block_signature_timestamp_for_block(block_index)
    }

    fn get_highest_known_block_index(&self) -> Result<Option<u64>, Self::Error> {
        self.record_call();
        self.inner.get_highest_known_block_index()
    }

    fn get_expired_invocations(
        &self,
        expiration: NaiveDateTime,
    ) -> Result<Vec<ExpiredInvocationRecord>, Self::Error> {
        self.record_call();
        self.inner.get_expired_invocations(expiration)
    }
}

fn create_view_store<DB>(
    db: DB,
    block_range: BlockRange,
    logger: Logger,
) -> ViewServer<SgxViewEnclave, DB, EpochShardingStrategy>
where
    DB: RecoveryDb + Clone + Send + Sync + 'static,
{
    let port = portpicker::pick_unused_port().expect("pick_unused_port");
    let sharding_strategy = EpochShardingStrategy::new(block_range);
    let responder_id = ResponderId::from_str(&format!("127.0.0.1:{port}")).unwrap();
    let uri = FogViewStoreUri::from_str(&format!(
        "insecure-fog-view-store://127.0.0.1:{port}?responder-id={responder_id}&sharding_strategy={sharding_strategy}"
    ))
    .unwrap();

    let config = MobileAcctViewConfig {
        chain_id: "local".to_string(),
        client_responder_id: responder_id,
        client_listen_uri: uri,
        client_auth_token_secret: None,
        omap_capacity: 512,
        admin_listen_uri: Default::default(),
        client_auth_token_max_lifetime: Default::default(),
        sharding_strategy: Epoch(sharding_strategy.clone()),
        postgres_config: Default::default(),
        block_query_batch_size: 2,
        db_polling_interval_ms: DB_POLLING_INTERVAL,
    };

    let enclave = SgxViewEnclave::new(
        get_enclave_path(mc_fog_view_enclave::ENCLAVE_FILE),
        config.client_responder_id.clone(),
        config.omap_capacity,
        logger.clone(),
    );

    let mut store = ViewServer::new(
        config,
        enclave,
        db,
        SystemTimeProvider,
        sharding_strategy,
        logger,
    );
    store.start();
    store
}

fn add_block(
    db: &impl RecoveryDb,
    invocation_id: &IngestInvocationId,
    block_index: u64,
    rng: &mut impl RngCore,
) {
    let (block, records) = random_block(rng, block_index, 5);
    db.add_block_data(invocation_id, &block, 0, &records)
        .unwrap();
}

fn wait_for_highest_processed_block_count<DB>(
    store: &ViewServer<SgxViewEnclave, DB, EpochShardingStrategy>,
    block_count: u64,
) where
    DB: RecoveryDb + Clone + Send + Sync + 'static,
{
    let deadline = Instant::now() + Duration::from_secs(60);
    while store.highest_processed_block_count() < block_count {
        assert!(
            Instant::now() < deadline,
            "view store did not reach highest_processed_block_count {block_count}, stuck at {}",
            store.highest_processed_block_count()
        );
        sleep(DB_POLLING_INTERVAL);
    }
}

#[test_with_logger]
fn view_store_stops_polling_db_after_loading_block_range(logger: Logger) {
    let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
    let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
    // Writes go straight to the SQL db so they don't count as polling.
    let sql_db = db_test_context.get_db_instance();
    let db = CountingRecoveryDb::new(sql_db.clone());

    let store = create_view_store(db.clone(), BlockRange::new(0, END_BLOCK), logger);

    let ingress_key = CompressedRistrettoPublic::from_random(&mut rng);
    sql_db.new_ingress_key(&ingress_key, 0).unwrap();
    let invocation_id = sql_db
        .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 0)
        .unwrap();

    // Load all but the last block in range. The store isn't done yet, so it
    // must keep polling for the rest.
    for block_index in 0..END_BLOCK - 1 {
        add_block(&sql_db, &invocation_id, block_index, &mut rng);
    }
    wait_for_highest_processed_block_count(&store, END_BLOCK - 1);
    assert!(
        db.num_calls_during(DB_POLLING_INTERVAL * 5) > 0,
        "view store stopped polling before loading its whole block range"
    );

    // Finish the range, and keep the chain growing past it.
    for block_index in END_BLOCK - 1..END_BLOCK + 5 {
        add_block(&sql_db, &invocation_id, block_index, &mut rng);
    }
    wait_for_highest_processed_block_count(&store, END_BLOCK);

    // Give the poll thread a few intervals to wind down, then confirm the
    // database is no longer touched.
    sleep(DB_POLLING_INTERVAL * 5);
    assert_eq!(
        db.num_calls_during(DB_POLLING_INTERVAL * 10),
        0,
        "view store kept polling after loading its whole block range"
    );

    assert_eq!(store.highest_processed_block_count(), END_BLOCK);
    assert!(
        db.max_requested_end_block() <= END_BLOCK,
        "view store fetched blocks past its block range: requested up to {}",
        db.max_requested_end_block()
    );
}
