// Copyright (c) 2018-2023 The MobileCoin Foundation

use mc_account_keys::{AccountKey, PublicAddress};
use mc_api::watcher::TimestampResultCode;
use mc_blockchain_types::BlockVersion;
use mc_common::{
    logger,
    logger::{log, Logger},
    time::SystemTimeProvider,
};
use mc_fog_ledger_connection::{KeyImageResultExtension, LedgerGrpcClient};
use mc_fog_ledger_enclave::LedgerSgxEnclave;
use mc_fog_ledger_server::{
    sharding_strategy::EpochShardingStrategy, KeyImageStoreServer, LedgerRouterConfig,
    LedgerRouterServer, LedgerStoreConfig, ShardingStrategy,
};
use mc_fog_ledger_test_infra::ShardProxyServer;
use mc_fog_test_infra::get_enclave_path;
use mc_fog_types::common::BlockRange;
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
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};
use tempfile::TempDir;
use url::Url;

const TEST_URL: &str = "http://www.my_url1.com";
const CHAIN_ID: &str = "local";

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
        ledger_db: Default::default(),
        watcher_db: Default::default(),
        admin_listen_uri: None,
        client_auth_token_secret: None,
        client_auth_token_max_lifetime: Default::default(),
        omap_capacity,
        sharding_strategy: ShardingStrategy::Epoch(EpochShardingStrategy::new(block_range)),
    }
}

fn add_block_to_ledger(
    ledger_db: &mut LedgerDB,
    recipients: &[PublicAddress],
    key_images: &[KeyImage],
    rng: &mut (impl CryptoRng + RngCore),
    watcher: &WatcherDB,
) -> u64 {
    let amount = Amount::new(10, Mob::ID);
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

fn populate_ledger(blocks_config: &BlockConfig, ledger: &mut LedgerDB, watcher: &WatcherDB) {
    let mut rng = thread_rng();

    let alice = AccountKey::random_with_fog(&mut rng);
    let recipients = vec![alice.default_subaddress()];
    // Origin block cannot have key images
    add_block_to_ledger(ledger, &recipients, &[], &mut rng, watcher);

    for block in blocks_config {
        let recipients: Vec<_> = block.keys().cloned().collect();
        let key_images: Vec<_> = block.values().flat_map(|x| x.clone()).collect();

        add_block_to_ledger(ledger, &recipients, &key_images, &mut rng, watcher);
    }
}

fn create_store(
    test_config: &StoreConfig,
    blocks_config: &BlockConfig,
    block_range: BlockRange,
    watcher_db_path: &Path,
    ledger_db_path: &Path,
    logger: Logger,
) -> KeyImageStoreServer<LedgerSgxEnclave, EpochShardingStrategy> {
    let uri = KeyImageStoreUri::from_str(&format!(
        "insecure-key-image-store://{}",
        test_config.address
    ))
    .unwrap();
    let block_range = test_config
        .block_range
        .as_ref()
        .unwrap_or(&block_range)
        .clone();
    let config = create_store_config(&uri, block_range.clone(), test_config.omap_capacity);
    let enclave = LedgerSgxEnclave::new(
        get_enclave_path(mc_fog_ledger_enclave::ENCLAVE_FILE),
        &config.client_responder_id,
        config.omap_capacity,
        logger.clone(),
    );

    let mut ledger = recreate_ledger_db(ledger_db_path);
    let watcher = setup_watcher_db(watcher_db_path.to_path_buf(), logger.clone());

    populate_ledger(blocks_config, &mut ledger, &watcher);

    let mut store = KeyImageStoreServer::new_from_config(
        config,
        enclave,
        ledger,
        watcher,
        EpochShardingStrategy::new(block_range),
        SystemTimeProvider,
        logger,
    );
    store.start();

    store
}

fn create_shard(config: &ShardConfig, _logger: Logger) -> ShardProxyServer {
    ShardProxyServer::new(
        &config.address,
        config
            .stores
            .iter()
            .map(|x| x.address.to_string())
            .collect(),
    )
}

fn create_router(
    test_config: &TestEnvironmentConfig,
    blocks_config: &BlockConfig,
    watcher_db_path: &Path,
    ledger_db_path: &Path,
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

    let mut ledger = recreate_ledger_db(ledger_db_path);
    let watcher = setup_watcher_db(watcher_db_path.to_path_buf(), logger.clone());

    populate_ledger(blocks_config, &mut ledger, &watcher);

    let config = LedgerRouterConfig {
        chain_id: "local".to_string(),
        ledger_db: ledger_db_path.to_path_buf(),
        watcher_db: watcher_db_path.to_path_buf(),
        shard_uris: test_config
            .shards
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
        omap_capacity: test_config.omap_capacity,
    };

    let enclave = LedgerSgxEnclave::new(
        get_enclave_path(mc_fog_ledger_enclave::ENCLAVE_FILE),
        &config.client_responder_id,
        config.omap_capacity,
        logger.clone(),
    );

    let mut router = LedgerRouterServer::new(config, enclave, ledger, watcher, logger);
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
    blocks_config: BlockConfig,
    grpc_env: Arc<grpcio::Environment>,
    logger: Logger,
) -> TestEnvironment {
    let mut shards = vec![];
    let mut stores = vec![];
    let mut tempdirs = vec![];
    for shard in config.shards.iter() {
        for store in shard.stores.iter() {
            let watcher_db_dir =
                TempDir::new().expect("Couldn't create temporary path for watcher DB");
            let ledger_db_dir =
                TempDir::new().expect("Couldn't create temporary path for ledger DB");
            stores.push(create_store(
                store,
                &blocks_config,
                shard.block_range.clone(),
                watcher_db_dir.path(),
                ledger_db_dir.path(),
                logger.clone(),
            ));
            tempdirs.push(watcher_db_dir);
            tempdirs.push(ledger_db_dir);
        }

        shards.push(create_shard(shard, logger.clone()));
    }

    let watcher_db_dir = TempDir::new().expect("Couldn't create temporary path for watcher DB");
    let ledger_db_dir = TempDir::new().expect("Couldn't create temporary path for ledger DB");
    let router = create_router(
        &config,
        &blocks_config,
        watcher_db_dir.path(),
        ledger_db_dir.path(),
        logger.clone(),
    );
    tempdirs.push(watcher_db_dir);
    tempdirs.push(ledger_db_dir);

    let router_client = create_router_client(&config, grpc_env, logger);

    TestEnvironment {
        stores,
        shards,
        _router: router,
        router_client,
        _tempdirs: tempdirs,
    }
}

struct TestEnvironment {
    router_client: LedgerGrpcClient,
    _router: LedgerRouterServer<LedgerSgxEnclave>,
    shards: Vec<ShardProxyServer>,
    stores: Vec<KeyImageStoreServer<LedgerSgxEnclave, EpochShardingStrategy>>,
    _tempdirs: Vec<TempDir>,
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        for shard in &mut self.shards {
            tokio::task::block_in_place(move || {
                tokio::runtime::Handle::current().block_on(async move {
                    shard.stop().await;
                })
            });
        }
        for store in &mut self.stores {
            store.stop();
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TestEnvironmentConfig {
    router_address: SocketAddr,
    router_admin_address: SocketAddr,
    shards: Vec<ShardConfig>,
    omap_capacity: u64,
}

#[derive(Serialize, Deserialize)]
struct ShardConfig {
    address: SocketAddr,
    block_range: BlockRange,
    stores: Vec<StoreConfig>,
}

#[derive(Serialize, Deserialize)]
struct StoreConfig {
    address: SocketAddr,
    block_range: Option<BlockRange>,
    omap_capacity: u64,
}

type BlockConfig = Vec<HashMap<PublicAddress, Vec<KeyImage>>>;

fn free_sockaddr() -> SocketAddr {
    let port = portpicker::pick_unused_port().unwrap();
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

#[tokio::test(flavor = "multi_thread")]
async fn smoke_test() {
    let logger = logger::create_test_logger("smoke_test".to_string());
    log::info!(logger, "test");
    // Three shards, three stores each, correct config, each stores three blocks,
    // each has three users with three keys each
    let num_shards = 3;
    let stores_per_shard = 3;
    let blocks_per_shard = 3;
    let mut rng = RngType::from_seed([0u8; 32]);
    let mut shards_config = vec![];
    for i in 0..num_shards {
        let mut stores_config = vec![];
        for _ in 0..stores_per_shard {
            let store = StoreConfig {
                address: free_sockaddr(),
                block_range: None,
                omap_capacity: 1000,
            };
            stores_config.push(store);
        }
        let shard = ShardConfig {
            address: free_sockaddr(),
            // the 1-block offset is because block 0 cannot contain key images
            block_range: BlockRange::new_from_length((i * blocks_per_shard) + 1, blocks_per_shard),
            stores: stores_config,
        };
        shards_config.push(shard);
    }
    let config = TestEnvironmentConfig {
        router_address: free_sockaddr(),
        router_admin_address: free_sockaddr(),
        shards: shards_config,
        omap_capacity: 1000,
    };

    let mut blocks_config = vec![];
    let mut key_index = 0;
    let num_blocks = blocks_per_shard * num_shards;
    let users_per_block = 3;
    let keys_per_user = 3;
    for _ in 0..num_blocks {
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

    let mut test_environment = create_env(config, blocks_config, grpc_env, logger.clone());

    // Check that we can get all the key images from each shard
    let keys_per_block = users_per_block * keys_per_user;
    for i in 0..key_index {
        let key = KeyImage::from(i);
        let response = test_environment
            .router_client
            .check_key_images(&[key])
            .await
            .expect("check_key_images failed");
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].key_image, key);
        assert_eq!(
            response.results[0].status(),
            Ok(Some((i / keys_per_block) + 1))
        );
        assert_eq!(
            response.results[0].timestamp_result_code,
            TimestampResultCode::TimestampFound as u32
        );
    }

    // Grab them all at once
    let keys: Vec<_> = (0..key_index).map(KeyImage::from).collect();
    let response = test_environment
        .router_client
        .check_key_images(&keys)
        .await
        .expect("check_key_images failed");
    assert_eq!(response.results.len(), key_index as usize);
    for i in 0..key_index {
        let key = KeyImage::from(i);
        assert_eq!(response.results[i as usize].key_image, key);
        assert_eq!(
            response.results[i as usize].status(),
            Ok(Some((i / keys_per_block) + 1))
        );
        assert_eq!(
            response.results[i as usize].timestamp_result_code,
            TimestampResultCode::TimestampFound as u32
        );
    }

    // Check that an unspent key image is unspent
    let key = KeyImage::from(126u64);
    let response = test_environment
        .router_client
        .check_key_images(&[key])
        .await
        .expect("check_key_images failed");
    assert_eq!(response.results.len(), 1);
    assert_eq!(response.results[0].key_image, key);
    assert_eq!(response.results[0].status(), Ok(None)); // Not spent
    assert_eq!(
        response.results[0].timestamp_result_code,
        TimestampResultCode::TimestampFound as u32
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn overlapping_stores() {
    let logger = logger::create_test_logger("overlapping_stores".to_string());
    log::info!(logger, "test");
    // Three shards, three stores each, correct config, each stores three blocks,
    // each has three users with three keys each - but the blocks overlap (so
    // total of 5 blocks)
    let num_shards = 3;
    let stores_per_shard = 3;
    let blocks_per_shard = 3;
    let mut rng = RngType::from_seed([0u8; 32]);
    let mut shards_config = vec![];
    for i in 0..num_shards {
        let mut stores_config = vec![];
        for _ in 0..stores_per_shard {
            let store = StoreConfig {
                address: free_sockaddr(),
                block_range: None,
                omap_capacity: 1000,
            };
            stores_config.push(store);
        }
        let shard = ShardConfig {
            address: free_sockaddr(),
            block_range: BlockRange::new_from_length(i + 1, blocks_per_shard),
            stores: stores_config,
        };
        shards_config.push(shard);
    }
    let config = TestEnvironmentConfig {
        router_address: free_sockaddr(),
        router_admin_address: free_sockaddr(),
        shards: shards_config,
        omap_capacity: 1000,
    };

    let mut blocks_config = vec![];
    let mut key_index = 0;
    let num_blocks = 5;
    let users_per_block = 3;
    let keys_per_user = 3;
    for _ in 0..num_blocks {
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

    let mut test_environment = create_env(config, blocks_config, grpc_env, logger.clone());

    // Check that we can get all the key images from each shard
    let keys_per_block = users_per_block * keys_per_user;
    for i in 0..key_index {
        let key = KeyImage::from(i);
        let response = test_environment
            .router_client
            .check_key_images(&[key])
            .await
            .expect("check_key_images failed");
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].key_image, key);
        assert_eq!(
            response.results[0].status(),
            Ok(Some((i / keys_per_block) + 1))
        );
        assert_eq!(
            response.results[0].timestamp_result_code,
            TimestampResultCode::TimestampFound as u32
        );
    }

    // Grab them all at once
    let keys: Vec<_> = (0..key_index).map(KeyImage::from).collect();
    let response = test_environment
        .router_client
        .check_key_images(&keys)
        .await
        .expect("check_key_images failed");
    assert_eq!(response.results.len(), key_index as usize);
    for i in 0..key_index {
        let key = KeyImage::from(i);
        assert_eq!(response.results[i as usize].key_image, key);
        assert_eq!(
            response.results[i as usize].status(),
            Ok(Some((i / keys_per_block) + 1))
        );
        assert_eq!(
            response.results[i as usize].timestamp_result_code,
            TimestampResultCode::TimestampFound as u32
        );
    }

    // Check that an unspent key image is unspent
    let key = KeyImage::from(126u64);
    let response = test_environment
        .router_client
        .check_key_images(&[key])
        .await
        .expect("check_key_images failed");
    assert_eq!(response.results.len(), 1);
    assert_eq!(response.results[0].key_image, key);
    assert_eq!(response.results[0].status(), Ok(None)); // Not spent
    assert_eq!(
        response.results[0].timestamp_result_code,
        TimestampResultCode::TimestampFound as u32
    );
}
