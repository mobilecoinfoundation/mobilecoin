// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Contains helper methods and structs used by the router integration test.

use grpcio::ChannelBuilder;
use mc_attest_net::{Client as AttestClient, RaClient};
use mc_attest_verifier::{MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
use mc_blockchain_types::{Block, BlockID, BlockIndex};
use mc_common::{
    logger::{log, Logger},
    time::SystemTimeProvider,
    ResponderId,
};
use mc_fog_api::view_grpc::FogViewStoreApiClient;
use mc_fog_recovery_db_iface::{AddBlockDataStatus, IngestInvocationId, RecoveryDb};
use mc_fog_sql_recovery_db::{test_utils::SqlRecoveryDbTestContext, SqlRecoveryDb};
use mc_fog_test_infra::get_enclave_path;
use mc_fog_types::{
    common::BlockRange,
    view::{FixedTxOutSearchResult, TxOutSearchResult, TxOutSearchResultCode},
    ETxOutRecord,
};
use mc_fog_uri::{FogViewRouterUri, FogViewStoreUri, FogViewUri};
use mc_fog_view_connection::{fog_view_router_client::FogViewRouterGrpcClient, FogViewGrpcClient};
use mc_fog_view_enclave::SgxViewEnclave;
use mc_fog_view_protocol::FogViewConnection;
use mc_fog_view_server::{
    config::{
        FogViewRouterConfig, MobileAcctViewConfig as ViewConfig, RouterClientListenUri,
        ShardingStrategy::Epoch,
    },
    fog_view_router_server::{FogViewRouterServer, Shard},
    server::ViewServer,
    sharding_strategy::EpochShardingStrategy,
};
use mc_transaction_core::BlockVersion;
use mc_util_grpc::{ConnectionUriGrpcioChannel, GrpcRetryConfig};
use mc_util_uri::{AdminUri, ConnectionUri};
use std::{
    str::FromStr,
    sync::{Arc, RwLock},
    thread::sleep,
    time::Duration,
};

const GRPC_RETRY_CONFIG: GrpcRetryConfig = GrpcRetryConfig {
    grpc_retry_count: 3,
    grpc_retry_millis: 20,
};

/// Contains the core structs used by router integration tests and manages their
/// drop order.
///
/// Note: We need to define a precise field drop order in order for this test to
/// not hang indefinitely upon completion, and wrapping each field in an
/// `Option` allows us to define drop order. If we don't do this, then the drop
/// order is defined by the field definition order, which is prone to error. I.e
/// simply reordering the fields would cause the test to fail without a clear
/// explanation as to why.

type TestViewServer =
    ViewServer<SgxViewEnclave, AttestClient, SqlRecoveryDb, EpochShardingStrategy>;

pub struct RouterTestEnvironment {
    pub router_server: Option<FogViewRouterServer<SgxViewEnclave, AttestClient>>,
    pub router_streaming_client: Option<FogViewRouterGrpcClient>,
    pub router_unary_client: Option<FogViewGrpcClient>,
    pub store_servers: Option<Vec<TestViewServer>>,
    pub db_test_context: Option<SqlRecoveryDbTestContext>,
}

impl RouterTestEnvironment {
    /// Creates a `RouterTestEnvironment` for the router integration tests.
    pub fn new(omap_capacity: u64, store_block_ranges: Vec<BlockRange>, logger: Logger) -> Self {
        let (db_test_context, store_servers, store_clients, shard_uris) =
            Self::create_view_stores(omap_capacity, store_block_ranges, logger.clone());
        let port = portpicker::pick_unused_port().expect("pick_unused_port");
        let router_uri =
            FogViewRouterUri::from_str(&format!("insecure-fog-view-router://127.0.0.1:{port}"))
                .unwrap();
        let port = portpicker::pick_unused_port().expect("pick_unused_port");
        let admin_listen_uri =
            AdminUri::from_str(&format!("insecure-mca://127.0.0.1:{port}")).unwrap();
        let config = FogViewRouterConfig {
            chain_id: "local".to_string(),
            client_responder_id: router_uri
                .responder_id()
                .expect("Could not get responder id for Fog View Router."),
            ias_api_key: Default::default(),
            shard_uris,
            ias_spid: Default::default(),
            client_listen_uri: RouterClientListenUri::Streaming(router_uri.clone()),
            client_auth_token_max_lifetime: Default::default(),
            client_auth_token_secret: None,
            omap_capacity,
            admin_listen_uri,
        };
        let router_server = Self::create_router_server(config, store_clients, &logger);
        let router_client = Self::create_router_streaming_client(router_uri, logger);
        Self {
            db_test_context: Some(db_test_context),
            router_server: Some(router_server),
            router_streaming_client: Some(router_client),
            router_unary_client: None,
            store_servers: Some(store_servers),
        }
    }

    /// Creates a `RouterTestEnvironment` for the router integration tests.
    pub fn new_unary(
        omap_capacity: u64,
        store_block_ranges: Vec<BlockRange>,
        logger: Logger,
    ) -> Self {
        let (db_test_context, store_servers, store_clients, shard_uris) =
            Self::create_view_stores(omap_capacity, store_block_ranges, logger.clone());
        let port = portpicker::pick_unused_port().expect("pick_unused_port");
        let router_uri =
            FogViewUri::from_str(&format!("insecure-fog-view://127.0.0.1:{port}")).unwrap();
        let port = portpicker::pick_unused_port().expect("pick_unused_port");
        let admin_listen_uri =
            AdminUri::from_str(&format!("insecure-mca://127.0.0.1:{port}")).unwrap();
        let chain_id = "local".to_string();
        let config = FogViewRouterConfig {
            chain_id: chain_id.clone(),
            client_responder_id: router_uri
                .responder_id()
                .expect("Could not get responder id for Fog View Router."),
            ias_api_key: Default::default(),
            ias_spid: Default::default(),
            shard_uris,
            client_listen_uri: RouterClientListenUri::Unary(router_uri.clone()),
            client_auth_token_max_lifetime: Default::default(),
            client_auth_token_secret: None,
            omap_capacity,
            admin_listen_uri,
        };
        let router_server = Self::create_router_server(config, store_clients, &logger);
        let router_client = Self::create_router_unary_client(chain_id, router_uri, logger);

        Self {
            db_test_context: Some(db_test_context),
            router_server: Some(router_server),
            router_unary_client: Some(router_client),
            router_streaming_client: None,
            store_servers: Some(store_servers),
        }
    }

    fn create_router_server(
        config: FogViewRouterConfig,
        shards: Arc<RwLock<Vec<Shard>>>,
        logger: &Logger,
    ) -> FogViewRouterServer<SgxViewEnclave, AttestClient> {
        let enclave = SgxViewEnclave::new(
            get_enclave_path(mc_fog_view_enclave::ENCLAVE_FILE),
            config.client_responder_id.clone(),
            config.omap_capacity,
            logger.clone(),
        );
        let ra_client =
            AttestClient::new(&config.ias_api_key).expect("Could not create IAS client");
        let mut router_server = FogViewRouterServer::new(
            config,
            enclave,
            ra_client,
            shards,
            SystemTimeProvider::default(),
            logger.clone(),
        );
        router_server.start();
        router_server
    }

    fn create_router_streaming_client(
        router_uri: FogViewRouterUri,
        logger: Logger,
    ) -> FogViewRouterGrpcClient {
        let grpcio_env = Arc::new(grpcio::EnvBuilder::new().build());
        let mut mr_signer_verifier =
            MrSignerVerifier::from(mc_fog_view_enclave_measurement::sigstruct());
        mr_signer_verifier.allow_hardening_advisory("INTEL-SA-00334");
        let mut verifier = Verifier::default();
        verifier.mr_signer(mr_signer_verifier).debug(DEBUG_ENCLAVE);

        FogViewRouterGrpcClient::new(router_uri, verifier, grpcio_env, logger)
    }

    fn create_router_unary_client(
        chain_id: String,
        router_uri: FogViewUri,
        logger: Logger,
    ) -> FogViewGrpcClient {
        let grpcio_env = Arc::new(grpcio::EnvBuilder::new().build());
        let mr_signer_verifier =
            MrSignerVerifier::from(mc_fog_view_enclave_measurement::sigstruct());
        let mut verifier = Verifier::default();
        verifier.mr_signer(mr_signer_verifier).debug(DEBUG_ENCLAVE);

        FogViewGrpcClient::new(
            chain_id,
            router_uri,
            GRPC_RETRY_CONFIG,
            verifier,
            grpcio_env,
            logger,
        )
    }

    /// Creates fog view stores with sane defaults.
    fn create_view_stores(
        omap_capacity: u64,
        store_block_ranges: Vec<BlockRange>,
        logger: Logger,
    ) -> (
        SqlRecoveryDbTestContext,
        Vec<TestViewServer>,
        Arc<RwLock<Vec<Shard>>>,
        Vec<FogViewStoreUri>,
    ) {
        let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
        let db = db_test_context.get_db_instance();
        let mut store_servers = Vec::new();
        let mut shards = Vec::new();
        let mut shard_uris: Vec<FogViewStoreUri> = Vec::new();

        for (i, store_block_range) in store_block_ranges.into_iter().enumerate() {
            let (store, store_uri) = {
                let port = portpicker::pick_unused_port().expect("pick_unused_port");
                let epoch_sharding_strategy = EpochShardingStrategy::new(store_block_range.clone());
                let responder_id = ResponderId::from_str(&format!("127.0.0.1:{port}"))
                    .expect("Could not create responder id");
                let uri = FogViewStoreUri::from_str(&format!(
                    "insecure-fog-view-store://127.0.0.1:{port}?responder-id={}&sharding_strategy={}",
                    responder_id,
                    epoch_sharding_strategy.to_string()
                ))
                .unwrap();

                let sharding_strategy = Epoch(epoch_sharding_strategy);
                shard_uris.push(uri.clone());

                let config = ViewConfig {
                    chain_id: "local".to_string(),
                    client_responder_id: uri.responder_id().unwrap(),
                    client_listen_uri: uri.clone(),
                    client_auth_token_secret: None,
                    omap_capacity,
                    ias_spid: Default::default(),
                    ias_api_key: Default::default(),
                    admin_listen_uri: Default::default(),
                    client_auth_token_max_lifetime: Default::default(),
                    sharding_strategy,
                    postgres_config: Default::default(),
                    block_query_batch_size: 2,
                };

                let enclave = SgxViewEnclave::new(
                    get_enclave_path(mc_fog_view_enclave::ENCLAVE_FILE),
                    config.client_responder_id.clone(),
                    config.omap_capacity,
                    logger.clone(),
                );

                let ra_client =
                    AttestClient::new(&config.ias_api_key).expect("Could not create IAS client");

                let Epoch(ref sharding_strategy) = config.sharding_strategy;
                let mut store = ViewServer::new(
                    config.clone(),
                    enclave,
                    db.clone(),
                    ra_client,
                    SystemTimeProvider::default(),
                    sharding_strategy.clone(),
                    logger.clone(),
                );
                store.start();
                (store, uri)
            };
            store_servers.push(store);

            let grpc_env = Arc::new(
                grpcio::EnvBuilder::new()
                    .name_prefix(format!("view-store-{i}"))
                    .build(),
            );
            let store_client = FogViewStoreApiClient::new(
                ChannelBuilder::default_channel_builder(grpc_env)
                    .keepalive_permit_without_calls(false)
                    .connect_to_uri(&store_uri, &logger),
            );
            let shard = Shard::new(store_uri, Arc::new(store_client), store_block_range);
            shards.push(shard);
        }

        let store_clients = Arc::new(RwLock::new(shards));

        (db_test_context, store_servers, store_clients, shard_uris)
    }
}

/// Defines the drop order for each field. Do not change the order or the test
/// will hang indefinitely.
impl Drop for RouterTestEnvironment {
    fn drop(&mut self) {
        // This needs to be dropped first because failure to do so keeps the gRPC
        // connection alive and the router server will never close down.
        self.router_streaming_client = None;
        self.router_server = None;
        self.store_servers = None;
        // This needs to be dropped after the servers because they have threads that are
        // constantly checking the db.
        self.db_test_context = None;
    }
}

/// Ensure that all provided ETxOutRecords are in the enclave, and that
/// non-existing ones aren't.
pub fn assert_e_tx_out_records(client: &mut FogViewGrpcClient, records: &[ETxOutRecord]) {
    // Construct an array of expected results that includes both records we expect
    // to find and records we expect not to find.
    let mut expected_fixed_results = Vec::new();
    for record in records {
        let fixed_result = FixedTxOutSearchResult::new(
            record.search_key.clone(),
            &record.payload,
            TxOutSearchResultCode::Found,
        );
        expected_fixed_results.push(fixed_result);
    }
    for i in 0..3 {
        let search_key = vec![i + 1; 16];
        let not_found_fixed_result = FixedTxOutSearchResult::new_not_found(search_key);
        expected_fixed_results.push(not_found_fixed_result);
    }
    expected_fixed_results.sort_by_key(|result| result.search_key.clone());
    let expected_results = expected_fixed_results
        .iter()
        .cloned()
        .map(|fixed_result| fixed_result.into())
        .collect::<Vec<TxOutSearchResult>>();

    let search_keys: Vec<_> = expected_fixed_results
        .iter()
        .map(|result| result.search_key.clone())
        .collect();

    let mut allowed_tries = 60usize;
    loop {
        let result = client.request(0, 0, search_keys.clone()).unwrap();

        let mut actual_fixed_results = result.fixed_tx_out_search_results.clone();
        actual_fixed_results.sort_by(|x, y| x.search_key.cmp(&y.search_key));
        let mut actual_results = result.tx_out_search_results.clone();
        actual_results.sort_by(|x, y| x.search_key.cmp(&y.search_key));

        let actual_fixed_matches = actual_fixed_results == expected_fixed_results;
        let actual_matches = actual_results == expected_results;
        if actual_fixed_matches && actual_matches {
            break;
        }
        if allowed_tries == 0 {
            panic!("Server did not catch up to database!");
        }
        allowed_tries -= 1;
        sleep(Duration::from_millis(1000));
    }
}

/// Adds block data with sane defaults
pub fn add_block_data(
    db: &SqlRecoveryDb,
    invocation_id: &IngestInvocationId,
    block_index: BlockIndex,
    cumulative_tx_out_count: u64,
    txs: &[ETxOutRecord],
) -> AddBlockDataStatus {
    db.add_block_data(
        invocation_id,
        &Block::new(
            BlockVersion::ZERO,
            &BlockID::default(),
            block_index,
            cumulative_tx_out_count,
            &Default::default(),
            &Default::default(),
        ),
        0,
        txs,
    )
    .unwrap()
}

/// Wait until first server has added stuff to ORAM. Since all view servers
/// should load ORAM at the same time, we could choose to wait for any view
/// server.
pub fn wait_for_highest_block_to_load(
    db: &SqlRecoveryDb,
    store_servers: &[TestViewServer],
    logger: &Logger,
) {
    let mut allowed_tries = 1000usize;
    loop {
        let db_num_blocks = db
            .get_highest_known_block_index()
            .unwrap()
            .map(|v| v + 1) // convert index to count
            .unwrap_or(0);
        let server_num_blocks = get_highest_processed_block_count(store_servers);
        if server_num_blocks > db_num_blocks {
            panic!(
                "Server num blocks should never be larger than db num blocks: {server_num_blocks} > {db_num_blocks}"
            );
        }
        if server_num_blocks == db_num_blocks {
            log::info!(logger, "Stopping, block {}", server_num_blocks);
            break;
        }
        log::info!(
            logger,
            "Waiting for server to catch up to db... {} < {}",
            server_num_blocks,
            db_num_blocks
        );
        if allowed_tries == 0 {
            panic!("Server did not catch up to database!");
        }
        allowed_tries -= 1;
        sleep(Duration::from_secs(1));
    }
}

/// Wait until a server has added a specific number of blocks to load.
pub fn wait_for_block_to_load(block_count: u64, store_servers: &[TestViewServer], logger: &Logger) {
    let mut allowed_tries = 60usize;
    loop {
        let server_num_blocks = get_highest_processed_block_count(store_servers);
        if server_num_blocks >= block_count {
            break;
        }
        log::info!(
            logger,
            "Waiting for server to catch up to db... {} < {}",
            server_num_blocks,
            block_count,
        );
        if allowed_tries == 0 {
            panic!("Server did not catch up to database!");
        }
        allowed_tries -= 1;
        sleep(Duration::from_millis(1000));
    }
}

/// Wait until a server has added a specific number of blocks to load.
pub fn wait_for_highest_processed_and_last_known(
    view_client: &mut FogViewGrpcClient,
    highest_processed_block_count: u64,
    last_known_block_count: u64,
) {
    let mut allowed_tries = 60usize;
    loop {
        let nonsense_search_keys = vec![vec![50u8]];
        let result = view_client.request(0, 0, nonsense_search_keys).unwrap();
        if result.highest_processed_block_count == highest_processed_block_count
            && result.last_known_block_count == last_known_block_count
        {
            break;
        }

        if allowed_tries == 0 {
            panic!("Server did not catch up to database! highest_processed_block_count = {}, last_known_block_count = {}", result.highest_processed_block_count, result.last_known_block_count);
        }
        allowed_tries -= 1;
        sleep(Duration::from_millis(1000));
    }
}

/// Find the highest processed number of blocks in a collection of store
/// servers.
pub fn get_highest_processed_block_count(store_servers: &[TestViewServer]) -> u64 {
    store_servers
        .iter()
        .map(|server| server.highest_processed_block_count())
        .max()
        .unwrap_or_default()
}

/// Creates a list of BlockRanges for store servers.
pub fn create_block_ranges(store_count: usize, blocks_per_store: u64) -> Vec<BlockRange> {
    let total_block_count = store_count * (blocks_per_store as usize);
    (0..total_block_count)
        .step_by(blocks_per_store as usize)
        .map(|i| BlockRange::new_from_length(i as u64, blocks_per_store))
        .collect::<Vec<_>>()
}
