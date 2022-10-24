
use mc_common::logger;
use mc_common::time::SystemTimeProvider;
use mc_common::logger::{log, Logger};
use mc_fog_ledger_server::{KeyImageStoreServer, LedgerStoreConfig, KeyImageRouterServer, LedgerRouterConfig};

use mc_fog_api::ledger_grpc::KeyImageStoreApiClient;

use mc_fog_uri::{KeyImageStoreUri, FogLedgerUri};
//use mc_util_uri::AdminUri;
//use mc_attest_core::ProviderId;
use mc_attest_verifier::{Verifier, MrSignerVerifier, DEBUG_ENCLAVE};
use mc_util_uri::ConnectionUri;
use mc_util_grpc::{GrpcRetryConfig, ConnectionUriGrpcioChannel};
use mc_fog_test_infra::get_enclave_path;
use mc_fog_ledger_enclave::LedgerSgxEnclave;
use mc_fog_ledger_connection::FogKeyImageGrpcClient;
use mc_ledger_db::test_utils::recreate_ledger_db;
use mc_watcher::watcher_db::WatcherDB;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tempdir::TempDir;
use url::Url;
use grpcio::ChannelBuilder;
//use core::time::Duration;

const TEST_URL: &str = "http://www.my_url1.com";
const CHAIN_ID: &str = "local";

fn setup_watcher_db(path: PathBuf, logger: Logger) -> WatcherDB {
    let url = Url::parse(TEST_URL).unwrap();

    // create does not open
    WatcherDB::create(&path).unwrap();
    WatcherDB::open_rw(&path, &[url], logger).unwrap()
}

// Test that a fog ledger connection is able to get valid merkle proofs by
fn create_store_config(store_uri: &KeyImageStoreUri, omap_capacity: u64) -> LedgerStoreConfig {
    LedgerStoreConfig {
        chain_id: CHAIN_ID.to_string(),
        client_responder_id: store_uri.responder_id().expect("Couldn't get responder ID for store"),
        client_listen_uri: store_uri.clone(),
        ledger_db: Default::default(),
        watcher_db: Default::default(),
        ias_api_key: Default::default(),
        ias_spid: Default::default(),
        admin_listen_uri: None,
        client_auth_token_secret: None,
        client_auth_token_max_lifetime: Default::default(),
        omap_capacity,
    }
}

fn create_stores(omap_capacity: u64, store_count: usize, grpc_env: Arc<grpcio::Environment>, logger: Logger) -> (Vec<KeyImageStoreServer>, Vec<KeyImageStoreApiClient>) {
    let mut stores = vec![];
    let mut store_clients = vec![];
    for _ in 0..store_count {
        let port = portpicker::pick_unused_port().expect("couldn't get unused port");
        let uri = KeyImageStoreUri::from_str(&format!("insecure-key-image-store://127.0.0.1:{}", port)).unwrap();
        let config = create_store_config(&uri, omap_capacity);
        let enclave = LedgerSgxEnclave::new(
            get_enclave_path(mc_fog_ledger_enclave::ENCLAVE_FILE),
            &config.client_responder_id.clone(),
            config.omap_capacity,
            logger.clone(),
        );
        
        let ledger_db_tmp = TempDir::new("fog-ledger").expect("Could not get test_ledger tempdir");
        let ledger_db_path = ledger_db_tmp.path();
        let ledger = recreate_ledger_db(ledger_db_path);

        let watcher_db_tmp = TempDir::new("fog-watcher").expect("Could not make tempdir for watcher db");
        let watcher_db_path = watcher_db_tmp.path();
        let watcher = setup_watcher_db(watcher_db_path.to_path_buf(), logger.clone());

        let store = KeyImageStoreServer::new(
            config,
            enclave,
            ledger,
            watcher,
            SystemTimeProvider::default(),
            logger.clone()
        );
        
        stores.push(store);
        
        let store_client = KeyImageStoreApiClient::new(
            ChannelBuilder::default_channel_builder(grpc_env.clone())
                .connect_to_uri(&uri, &logger),
        );
        
        store_clients.push(store_client);
    }
    
    (stores, store_clients)
}

const GRPC_RETRY_CONFIG: GrpcRetryConfig = GrpcRetryConfig {
    grpc_retry_count: 3,
    grpc_retry_millis: 20,
};

fn create_router(omap_capacity: u64, shards: Vec<KeyImageStoreApiClient>, grpc_env: Arc<grpcio::Environment>, logger: Logger) -> (KeyImageRouterServer, FogKeyImageGrpcClient) {
    let port = portpicker::pick_unused_port().expect("couldn't get unused port");
    let uri = FogLedgerUri::from_str(&format!("insecure-fog-ledger://127.0.0.1:{}", port)).unwrap();

    let config = LedgerRouterConfig {
        client_responder_id: uri.responder_id().expect("Couldn't get responder ID for router"),
        client_listen_uri: uri.clone(),
        omap_capacity,
    };

    let enclave = LedgerSgxEnclave::new(
        get_enclave_path(mc_fog_ledger_enclave::ENCLAVE_FILE),
        &config.client_responder_id.clone(),
        config.omap_capacity,
        logger.clone(),
    );

    let router = KeyImageRouterServer::new(
        config,
        enclave,
        shards,
        logger.clone()
    );

    let mut mr_signer_verifier =
        MrSignerVerifier::from(mc_fog_ledger_enclave_measurement::sigstruct());
    mr_signer_verifier.allow_hardening_advisories(
        mc_fog_ledger_enclave_measurement::HARDENING_ADVISORIES,
    );

    let mut verifier = Verifier::default();
    verifier.mr_signer(mr_signer_verifier).debug(DEBUG_ENCLAVE);

    let router_client = FogKeyImageGrpcClient::new(
        CHAIN_ID.to_string(),
        uri,
        GRPC_RETRY_CONFIG,
        verifier,
        grpc_env.clone(),
        logger,
    );
    
    (router, router_client)
}

#[test]
fn router_integration_test() {
    let (logger, _global_logger_guard) =
        logger::create_app_logger(logger::o!());
    log::info!(logger, "test");
    
    let omap_capacity = 1000;
    let num_stores = 5;
    
    let grpc_env = Arc::new(grpcio::EnvBuilder::new().build());
    
    let (_stores, store_clients) = create_stores(omap_capacity, num_stores, grpc_env.clone(), logger.clone());
    // router talks directly to stores for these tests
    // shard tests are done in CI/CD
    let (_router, _router_client) = create_router(omap_capacity, store_clients, grpc_env, logger);
    
    unimplemented!();
}
