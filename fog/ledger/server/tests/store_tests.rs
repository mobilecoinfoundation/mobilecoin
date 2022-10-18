use std::{path::PathBuf, str::FromStr, sync::Arc};

use mc_attest_net::{Client as AttestClient, RaClient};
use mc_attest_verifier::{MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
use mc_common::{logger::{Logger, test_with_logger}, ResponderId, time::SystemTimeProvider};
use mc_crypto_rand::{CryptoRng, RngCore};
use mc_fog_ledger_enclave::{LedgerSgxEnclave, ENCLAVE_FILE};
use mc_fog_ledger_server::{LedgerStoreConfig, KeyImageStoreServer};
use mc_fog_uri::KeyImageStoreScheme;
use mc_ledger_db::{LedgerDB, test_utils::recreate_ledger_db};
use mc_util_test_helper::{SeedableRng, RngType};
use mc_util_uri::{Uri, UriScheme};
use mc_watcher::watcher_db::WatcherDB;
use tempdir::TempDir;
use url::Url; 

pub fn responder_id_for_test(test_name: &'static str, port: u16) -> ResponderId { 
    ResponderId(format!("fog://{}.fog.test:{}", test_name, port))
}

pub struct TestingContext<R: RngCore + CryptoRng> { 
    pub enclave: LedgerSgxEnclave,
    pub ledger: LedgerDB,
    pub ledger_path: PathBuf,
    pub responder_id: ResponderId,
    pub rng: R, 
    pub tempdir: TempDir,
    pub tx_source_url: Url,
    pub watcher: WatcherDB,
    pub watcher_path: PathBuf,
}

impl<R: RngCore + CryptoRng> TestingContext<R> {
    pub fn new(test_name: &'static str, 
            port: u16, 
            omap_capacity: u64, 
            logger: Logger,
            rng: R)
            -> Self {
        // Set up our directories. 
        let test_dir_name = format!("fog_ledger_test_{}", test_name);
        let tempdir = TempDir::new(&test_dir_name).expect("Could not produce test_ledger tempdir");
        let test_path = PathBuf::from(tempdir.path());
        let user_keys_path = test_path.join(PathBuf::from("keys/")); 
        if !user_keys_path.exists() { 
            std::fs::create_dir(&user_keys_path).unwrap();
        }

        // This ID needs to match the host:port clients use in their URI when referencing the host node.
        let responder_id = responder_id_for_test(test_name, port);

        let enclave_path = std::env::current_exe()
            .expect("Could not get the path of our executable")
            .with_file_name(ENCLAVE_FILE);
            
        let enclave = LedgerSgxEnclave::new(
            enclave_path,
            &responder_id,
            omap_capacity,
            logger.clone(),
        );

        // Make LedgerDB
        let ledger_path = test_path.join(PathBuf::from("fog_ledger"));
        let ledger = recreate_ledger_db(ledger_path.as_path());

        // Set up wallet db. 
        let test_url_name = format!("http://{}.wallet.test.test", test_name);
        let url = Url::parse(&test_url_name).unwrap();

        let db_tmp = test_path.join(PathBuf::from("wallet_db"));
        WatcherDB::create(db_tmp.as_path()).unwrap();
        let watcher_path = db_tmp.join(PathBuf::from("watcher_db"));
        let watcher = WatcherDB::open_rw(watcher_path.as_path(), &[url.clone()], logger).unwrap();

        Self {
            enclave,
            ledger,
            ledger_path,
            responder_id,
            rng,
            tempdir,
            tx_source_url: url,
            watcher,
            watcher_path,
        }
    }
}

#[test_with_logger]
pub fn simple_roundtrip(logger: Logger) { 
    const PORT: u16 = 3228;
    const TEST_NAME: &'static str = "key_image_store_simple_roundtrip";
    const CHAIN_ID: &'static str = TEST_NAME;
    const OMAP_CAPACITY: u64 = 255; 

    let rng = RngType::from_entropy(); 
    let TestingContext { 
        enclave,
        ledger,
        ledger_path,
        responder_id,
        rng: _rng, 
        tempdir: _tempdir,
        tx_source_url: _tx_source_url,
        watcher,
        watcher_path,
    } = TestingContext::new(TEST_NAME, PORT, OMAP_CAPACITY, logger.clone(), rng);

    let uri_string = format!(
        "{}://127.0.0.1:{}",
        KeyImageStoreScheme::SCHEME_INSECURE,
        PORT,
    );
    let client_listen_uri: Uri<KeyImageStoreScheme> = Uri::from_str(&uri_string).unwrap();

    let config = LedgerStoreConfig {
        chain_id: CHAIN_ID.to_string(),
        client_responder_id: responder_id,
        client_listen_uri,
        ledger_db: ledger_path,
        watcher_db: watcher_path,
        ias_api_key: Default::default(),
        ias_spid: Default::default(),
        admin_listen_uri: Default::default(),
        client_auth_token_secret: None,
        client_auth_token_max_lifetime: Default::default(),
        omap_capacity: OMAP_CAPACITY,
    };

    let mut store_server = KeyImageStoreServer::new_from_config(
        config.clone(), 
        enclave, 
        ledger, 
        watcher,
        SystemTimeProvider::default(), 
        logger.clone()
    );

    store_server.start();

    let _ra_client =
        AttestClient::new(&config.ias_api_key).expect("Could not create IAS client");

    let _grpc_env = Arc::new(grpcio::EnvBuilder::new().build());


    // Make ledger enclave client
    let mut mr_signer_verifier =
        MrSignerVerifier::from(mc_fog_ledger_enclave_measurement::sigstruct());
    mr_signer_verifier.allow_hardening_advisories(
        mc_fog_ledger_enclave_measurement::HARDENING_ADVISORIES,
    );

    let mut verifier = Verifier::default();
    verifier.mr_signer(mr_signer_verifier).debug(DEBUG_ENCLAVE);
}  