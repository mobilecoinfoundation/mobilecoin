
use mc_common::logger;
use mc_common::time::SystemTimeProvider;
use mc_common::logger::{log, Logger};
use mc_fog_ledger_server::{KeyImageStoreServer, LedgerStoreConfig};

use mc_fog_uri::KeyImageStoreUri;
//use mc_util_uri::AdminUri;
//use mc_attest_core::ProviderId;
use mc_util_uri::ConnectionUri;
use mc_fog_test_infra::get_enclave_path;
use mc_fog_ledger_enclave::LedgerSgxEnclave;
use mc_ledger_db::test_utils::recreate_ledger_db;
use mc_watcher::watcher_db::WatcherDB;
use std::path::PathBuf;
use std::str::FromStr;
use tempdir::TempDir;
use url::Url;
//use core::time::Duration;

const TEST_URL: &str = "http://www.my_url1.com";

fn setup_watcher_db(path: PathBuf, logger: Logger) -> WatcherDB {
    let url = Url::parse(TEST_URL).unwrap();

    // create does not open
    WatcherDB::create(&path).unwrap();
    WatcherDB::open_rw(&path, &[url], logger).unwrap()
}

// Test that a fog ledger connection is able to get valid merkle proofs by
fn create_store_config(store_uri: &KeyImageStoreUri, omap_capacity: u64) -> LedgerStoreConfig {
    LedgerStoreConfig {
        chain_id: "local".to_string(),
        client_responder_id: store_uri.responder_id().expect("Couldn't get responder ID for router"),
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

fn create_stores(omap_capacity: u64, store_count: usize, logger: Logger) -> Vec<KeyImageStoreServer> {
    let mut stores = vec![];
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
    }
    unimplemented!();
}

#[test]
fn router_integration_test() {
    let (logger, _global_logger_guard) =
        logger::create_app_logger(logger::o!());
    log::info!(logger, "test");
    
    let _stores = create_stores(1000, 5, logger);
}
