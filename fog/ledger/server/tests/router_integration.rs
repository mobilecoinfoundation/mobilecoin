// Copyright (c) 2018-2023 The MobileCoin Foundation

use mc_account_keys::{AccountKey, PublicAddress};
use mc_api::watcher::TimestampResultCode;
use mc_blockchain_types::BlockVersion;
use mc_common::{
    logger::{log, Logger},
    time::SystemTimeProvider,
};
use mc_fog_block_provider::LocalBlockProvider;
use mc_fog_ledger_connection::{KeyImageResultExtension, LedgerGrpcClient};
use mc_fog_ledger_enclave::LedgerSgxEnclave;
use mc_fog_ledger_server::{
    sharding_strategy::EpochShardingStrategy, KeyImageStoreServer, LedgerRouterConfig,
    LedgerRouterServer, LedgerStoreConfig, ShardingStrategy,
};
use mc_fog_test_infra::get_enclave_path;
use mc_fog_types::{common::BlockRange, ledger::KeyImageResult};
use mc_fog_uri::{FogLedgerUri, KeyImageStoreUri};
use mc_ledger_db::{test_utils::recreate_ledger_db, LedgerDB};
use mc_rand::{CryptoRng, RngCore};
use mc_transaction_core::{ring_signature::KeyImage, tokens::Mob, Amount, Token};
use mc_util_test_helper::{RngType, SeedableRng};
use mc_util_uri::{AdminUri, ConnectionUri};
use mc_watcher::watcher_db::WatcherDB;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tempfile::TempDir;
use url::Url;

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TEST_URL: &str = "http://www.my_url1.com";
const CHAIN_ID: &str = "local";

fn assert_key_image_unspent(key: &KeyImage, result: &KeyImageResult) {
    assert_eq!(result.key_image, *key);
    // None in the status means not spent.
    assert_eq!(result.status(), Ok(None));
}

fn assert_key_image_spent(key: &KeyImage, result: &KeyImageResult, block_index: u64) {
    assert_eq!(result.key_image, *key);
    assert_eq!(result.status(), Ok(Some(block_index)));
    assert_eq!(
        result.timestamp_result_code,
        TimestampResultCode::TimestampFound as u32
    );
}

fn setup_watcher_db(path: PathBuf, logger: Logger) -> WatcherDB {
    let url = Url::parse(TEST_URL).unwrap();

    // create does not open
    WatcherDB::create(&path).unwrap();
    WatcherDB::open_rw(&path, &[url], logger).unwrap()
}

fn create_store_config(
    store_uri: &KeyImageStoreUri,
    block_range: BlockRange,
    omap_capacity: u64,
) -> LedgerStoreConfig {
    LedgerStoreConfig {
        chain_id: CHAIN_ID.to_string(),
        client_responder_id: store_uri
            .responder_id()
            .expect("Couldn't get responder ID for store"),
        client_listen_uri: store_uri.clone(),
        ledger_db: Some(Default::default()),
        watcher_db: Some(Default::default()),
        mobilecoind_uri: None,
        admin_listen_uri: None,
        client_auth_token_secret: None,
        client_auth_token_max_lifetime: Default::default(),
        omap_capacity,
        sharding_strategy: ShardingStrategy::Epoch(EpochShardingStrategy::new(block_range)),
        poll_interval: POLL_INTERVAL,
    }
}

fn add_block_to_ledger(
    block_provider: &mut LocalBlockProvider<LedgerDB>,
    recipients: &[PublicAddress],
    key_images: &[KeyImage],
    rng: &mut (impl CryptoRng + RngCore),
) -> u64 {
    let amount = Amount::new(10, Mob::ID);
    let ledger_db = &mut block_provider.ledger;
    let block_data = mc_ledger_db::test_utils::add_block_to_ledger(
        ledger_db,
        BlockVersion::MAX,
        recipients,
        amount,
        key_images,
        rng,
    )
    .expect("failed to add block");
    let block_index = block_data.block().index;

    let signature = block_data.signature().expect("missing signature");
    let watcher = block_provider.watcher.as_ref().expect("missing watcher");
    for src_url in watcher.get_config_urls().unwrap().iter() {
        watcher
            .add_block_signature(
                src_url,
                block_index,
                signature.clone(),
                format!("00/{block_index}"),
            )
            .expect("Could not add block signature");
    }

    block_index + 1
}

fn seed_block_provider(block_provider: &mut LocalBlockProvider<LedgerDB>) {
    let mut rng = thread_rng();

    let alice = AccountKey::random_with_fog(&mut rng);
    let recipients = vec![alice.default_subaddress()];
    // Origin block cannot have key images
    add_block_to_ledger(block_provider, &recipients, &[], &mut rng);
}

fn populate_block_provider<'a>(
    block_provider: &mut LocalBlockProvider<LedgerDB>,
    blocks_config: impl IntoIterator<Item = &'a HashMap<PublicAddress, Vec<KeyImage>>>,
) {
    let mut rng = thread_rng();

    for block in blocks_config.into_iter() {
        let recipients: Vec<_> = block.keys().cloned().collect();
        let key_images: Vec<_> = block.values().flat_map(|x| x.clone()).collect();

        add_block_to_ledger(block_provider, &recipients, &key_images, &mut rng);
    }

    // The stores are running on separate threads. We wait 16 times the
    // their POLL_INTERVAL to account for number of threads in CI.
    // This helps to ensure all the stores have had time to process the new
    // blocks
    std::thread::sleep(POLL_INTERVAL * 16);
}

fn create_store(
    test_config: &StoreConfig,
    block_provider: Box<LocalBlockProvider<LedgerDB>>,
    logger: Logger,
) -> KeyImageStoreServer<LedgerSgxEnclave, EpochShardingStrategy> {
    let uri = KeyImageStoreUri::from_str(&format!(
        "insecure-key-image-store://{}",
        test_config.address
    ))
    .unwrap();
    let block_range = test_config.block_range.clone();
    let config = create_store_config(&uri, block_range.clone(), test_config.omap_capacity);
    let enclave = LedgerSgxEnclave::new(
        get_enclave_path(mc_fog_ledger_enclave::ENCLAVE_FILE),
        &config.client_responder_id,
        config.omap_capacity,
        logger.clone(),
    );

    let mut store = KeyImageStoreServer::new_from_config(
        config,
        enclave,
        block_provider,
        EpochShardingStrategy::new(block_range),
        SystemTimeProvider,
        logger,
    );
    store.start();

    store
}

fn create_router(
    test_config: &TestEnvironmentConfig,
    block_provider: Box<LocalBlockProvider<LedgerDB>>,
    logger: Logger,
) -> LedgerRouterServer<LedgerSgxEnclave> {
    let uri = FogLedgerUri::from_str(&format!(
        "insecure-fog-ledger://{}",
        test_config.router_address
    ))
    .unwrap();
    let admin_uri = AdminUri::from_str(&format!(
        "insecure-mca://{}",
        test_config.router_admin_address
    ))
    .unwrap();

    let config = LedgerRouterConfig {
        chain_id: "local".to_string(),
        ledger_db: None,
        watcher_db: None,
        mobilecoind_uri: None,
        shard_uris: test_config
            .stores
            .iter()
            .map(|x| {
                KeyImageStoreUri::from_str(&format!("insecure-key-image-store://{}", x.address))
                    .unwrap()
            })
            .collect(),
        client_responder_id: uri
            .responder_id()
            .expect("Couldn't get responder ID for router"),
        client_listen_uri: uri,
        admin_listen_uri: admin_uri,
        client_auth_token_secret: None,
        client_auth_token_max_lifetime: Default::default(),
        query_retries: 3,
    };

    let enclave = LedgerSgxEnclave::new(
        get_enclave_path(mc_fog_ledger_enclave::ENCLAVE_FILE),
        &config.client_responder_id,
        0,
        logger.clone(),
    );

    let mut router = LedgerRouterServer::new(config, enclave, block_provider, logger);
    router.start();
    router
}

fn create_router_client(
    config: &TestEnvironmentConfig,
    grpc_env: Arc<grpcio::Environment>,
    logger: Logger,
) -> LedgerGrpcClient {
    let uri = FogLedgerUri::from_str(&format!("insecure-fog-ledger://{}", config.router_address))
        .unwrap();

    let identity = mc_fog_ledger_enclave_measurement::mr_signer_identity(None);
    LedgerGrpcClient::new(uri, [identity], grpc_env, logger)
}

fn create_env(
    config: TestEnvironmentConfig,
    grpc_env: Arc<grpcio::Environment>,
    logger: Logger,
) -> TestEnvironment {
    let watcher_db_dir = TempDir::new().expect("Couldn't create temporary path for watcher DB");
    let ledger_db_dir = TempDir::new().expect("Couldn't create temporary path for ledger DB");
    let ledger = recreate_ledger_db(ledger_db_dir.path());
    let watcher = setup_watcher_db(watcher_db_dir.path().to_path_buf(), logger.clone());
    let mut block_provider = LocalBlockProvider::new(ledger, watcher);
    seed_block_provider(&mut block_provider);

    let mut stores = vec![];
    for store in config.stores.iter() {
        stores.push(create_store(store, block_provider.clone(), logger.clone()));
    }

    let router = create_router(&config, block_provider.clone(), logger.clone());

    let router_client = create_router_client(&config, grpc_env, logger);

    TestEnvironment {
        stores,
        _router: router,
        router_client,
        block_provider,
        _tempdirs: vec![watcher_db_dir, ledger_db_dir],
    }
}

struct TestEnvironment {
    router_client: LedgerGrpcClient,
    _router: LedgerRouterServer<LedgerSgxEnclave>,
    stores: Vec<KeyImageStoreServer<LedgerSgxEnclave, EpochShardingStrategy>>,
    block_provider: Box<LocalBlockProvider<LedgerDB>>,
    _tempdirs: Vec<TempDir>,
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        for store in &mut self.stores {
            store.stop();
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TestEnvironmentConfig {
    router_address: SocketAddr,
    router_admin_address: SocketAddr,
    stores: Vec<StoreConfig>,
}

#[derive(Serialize, Deserialize)]
struct StoreConfig {
    address: SocketAddr,
    block_range: BlockRange,
    omap_capacity: u64,
}

fn free_sockaddr() -> SocketAddr {
    let port = portpicker::pick_unused_port().unwrap();
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

#[tokio::test(flavor = "multi_thread")]
async fn smoke_test() {
    let logger = mc_common::logger::create_test_logger(stdext::function_name!().to_string());
    log::info!(logger, "test");
    let genesis_store = StoreConfig {
        address: free_sockaddr(),
        block_range: BlockRange::new_from_length(0, 1),
        omap_capacity: 1000,
    };
    let mut stores_config = vec![genesis_store];

    // Three stores, correct config, each stores three blocks,
    // each has three users with three keys each
    let num_stores = 3;
    let blocks_per_store = 3;
    let mut rng = RngType::from_seed([0u8; 32]);
    for i in 0..num_stores {
        let store = StoreConfig {
            address: free_sockaddr(),
            // the 1-block offset is because block 0 cannot contain key images
            block_range: BlockRange::new_from_length((i * blocks_per_store) + 1, blocks_per_store),
            omap_capacity: 1000,
        };
        stores_config.push(store);
    }
    let config = TestEnvironmentConfig {
        router_address: free_sockaddr(),
        router_admin_address: free_sockaddr(),
        stores: stores_config,
    };

    let mut blocks_config = vec![];
    let mut key_index = 0;
    let blocks_to_add = blocks_per_store * num_stores;
    let users_per_block = 3;
    let keys_per_user = 3;
    for _ in 0..blocks_to_add {
        let mut block = HashMap::new();
        for _ in 0..users_per_block {
            let account = AccountKey::random_with_fog(&mut rng);
            let mut keys = vec![];
            for _ in 0..keys_per_user {
                keys.push(KeyImage::from(key_index));
                key_index += 1;
            }
            block.insert(account.default_subaddress(), keys);
        }
        blocks_config.push(block);
    }

    let grpc_env = Arc::new(grpcio::EnvBuilder::new().build());

    let mut test_environment = create_env(config, grpc_env, logger.clone());

    let new_transactions = users_per_block * blocks_to_add;
    for (block_index, block) in blocks_config
        .iter()
        .enumerate()
        .map(|(i, e)| ((i + 1) as u64, e))
    {
        for keys in block.values() {
            for key in keys {
                let response = test_environment
                    .router_client
                    .check_key_images(&[*key])
                    .await
                    .expect("check_key_images failed");
                // We should always get a result to prevent side channel
                // attacks from determining whether a key image was spent.
                assert_eq!(response.results.len(), 1);
                assert_key_image_unspent(key, &response.results[0]);

                assert_eq!(response.num_blocks, block_index);
                assert_eq!(
                    response.global_txo_count,
                    ((block_index - 1) * users_per_block) + 1
                );
                let expected_block_version = if block_index == 1 {
                    0
                } else {
                    *BlockVersion::MAX
                };
                assert_eq!(response.latest_block_version, expected_block_version);
                assert_eq!(response.max_block_version, *BlockVersion::MAX);
            }
        }
        populate_block_provider(&mut test_environment.block_provider, [block]);
        for keys in block.values() {
            for key in keys {
                let response = test_environment
                    .router_client
                    .check_key_images(&[*key])
                    .await
                    .expect("check_key_images failed");
                assert_eq!(response.results.len(), 1);
                assert_key_image_spent(key, &response.results[0], block_index);

                assert_eq!(response.num_blocks, block_index + 1);
                assert_eq!(
                    response.global_txo_count,
                    (block_index * users_per_block) + 1
                );
                assert_eq!(response.latest_block_version, *BlockVersion::MAX);
                assert_eq!(response.max_block_version, *BlockVersion::MAX);
            }
        }
    }

    // Grab them all at once
    let keys_per_block = users_per_block * keys_per_user;
    let keys: Vec<_> = (0..key_index).map(KeyImage::from).collect();
    let response = test_environment
        .router_client
        .check_key_images(&keys)
        .await
        .expect("check_key_images failed");
    assert_eq!(response.results.len(), key_index as usize);
    for i in 0..key_index {
        let key = KeyImage::from(i);

        let block_index = (i / keys_per_block) + 1;
        assert_key_image_spent(&key, &response.results[i as usize], block_index);
    }
    assert_eq!(response.num_blocks, blocks_to_add + 1);
    assert_eq!(response.global_txo_count, new_transactions + 1);
    assert_eq!(response.latest_block_version, *BlockVersion::MAX);
    assert_eq!(response.max_block_version, *BlockVersion::MAX);
}

#[tokio::test(flavor = "multi_thread")]
async fn overlapping_stores() {
    let logger = mc_common::logger::create_test_logger(stdext::function_name!().to_string());
    log::info!(logger, "test");
    let genesis_store = StoreConfig {
        address: free_sockaddr(),
        block_range: BlockRange::new_from_length(0, 1),
        omap_capacity: 1000,
    };
    let mut stores_config = vec![genesis_store];

    // Three stores, correct config, each stores three blocks,
    // each has three users with three keys each - but the blocks overlap (so
    // total of 5 blocks)
    let num_stores = 3;
    let blocks_per_store = 3;
    let mut rng = RngType::from_seed([0u8; 32]);
    for i in 0..num_stores {
        let store = StoreConfig {
            address: free_sockaddr(),
            block_range: BlockRange::new_from_length(i + 1, blocks_per_store),
            omap_capacity: 1000,
        };
        stores_config.push(store);
    }
    let config = TestEnvironmentConfig {
        router_address: free_sockaddr(),
        router_admin_address: free_sockaddr(),
        stores: stores_config,
    };

    let mut blocks_config = vec![];
    let mut key_index = 0;
    let blocks_to_add = 5;
    let users_per_block = 3;
    let keys_per_user = 3;
    for _ in 0..blocks_to_add {
        let mut block = HashMap::new();
        for _ in 0..users_per_block {
            let account = AccountKey::random_with_fog(&mut rng);
            let mut keys = vec![];
            for _ in 0..keys_per_user {
                keys.push(KeyImage::from(key_index));
                key_index += 1;
            }
            block.insert(account.default_subaddress(), keys);
        }
        blocks_config.push(block);
    }

    let grpc_env = Arc::new(grpcio::EnvBuilder::new().build());

    let mut test_environment = create_env(config, grpc_env, logger.clone());

    let new_transactions = users_per_block * blocks_to_add;
    for (block_index, block) in blocks_config
        .iter()
        .enumerate()
        .map(|(i, e)| ((i + 1) as u64, e))
    {
        for keys in block.values() {
            for key in keys {
                let response = test_environment
                    .router_client
                    .check_key_images(&[*key])
                    .await
                    .expect("check_key_images failed");
                // We should always get a result to prevent side channel
                // attacks from determining whether a key image was spent.
                assert_eq!(response.results.len(), 1);
                assert_key_image_unspent(key, &response.results[0]);

                assert_eq!(response.num_blocks, block_index);
                assert_eq!(
                    response.global_txo_count,
                    ((block_index - 1) * users_per_block) + 1
                );
                let expected_block_version = if block_index == 1 {
                    0
                } else {
                    *BlockVersion::MAX
                };
                assert_eq!(response.latest_block_version, expected_block_version);
                assert_eq!(response.max_block_version, *BlockVersion::MAX);
            }
        }
        populate_block_provider(&mut test_environment.block_provider, [block]);
        for keys in block.values() {
            for key in keys {
                let response = test_environment
                    .router_client
                    .check_key_images(&[*key])
                    .await
                    .expect("check_key_images failed");
                assert_eq!(response.results.len(), 1);
                assert_key_image_spent(key, &response.results[0], block_index);

                assert_eq!(response.num_blocks, block_index + 1);
                assert_eq!(
                    response.global_txo_count,
                    (block_index * users_per_block) + 1
                );
                assert_eq!(response.latest_block_version, *BlockVersion::MAX);
                assert_eq!(response.max_block_version, *BlockVersion::MAX);
            }
        }
    }

    // Grab them all at once
    let keys_per_block = users_per_block * keys_per_user;
    let keys: Vec<_> = (0..key_index).map(KeyImage::from).collect();
    let response = test_environment
        .router_client
        .check_key_images(&keys)
        .await
        .expect("check_key_images failed");
    assert_eq!(response.results.len(), key_index as usize);
    for i in 0..key_index {
        let key = KeyImage::from(i);

        let block_index = (i / keys_per_block) + 1;
        assert_key_image_spent(&key, &response.results[i as usize], block_index);
    }
    assert_eq!(response.num_blocks, blocks_to_add + 1);
    assert_eq!(response.global_txo_count, new_transactions + 1);
    assert_eq!(response.latest_block_version, *BlockVersion::MAX);
    assert_eq!(response.max_block_version, *BlockVersion::MAX);
}
