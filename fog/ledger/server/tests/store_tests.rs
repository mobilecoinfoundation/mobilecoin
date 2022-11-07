use std::{
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
};

use mc_attest_ake::{AuthResponseInput, ClientInitiate, Start, Transition};
use mc_attest_api::attest;
use mc_attest_enclave_api::{ClientSession, EnclaveMessage, NonceSession};
use mc_attest_net::{Client as AttestClient, RaClient};
use mc_attest_verifier::Verifier;
use mc_blockchain_types::MAX_BLOCK_VERSION;
use mc_common::{
    logger::{test_with_logger, Logger},
    ResponderId,
};
use mc_crypto_keys::X25519;
use mc_crypto_rand::{CryptoRng, RngCore};
use mc_fog_api::ledger_grpc;
use mc_fog_ledger_enclave::{KeyImageData, LedgerEnclave, LedgerSgxEnclave, ENCLAVE_FILE};
use mc_fog_ledger_enclave_api::UntrustedKeyImageQueryResponse;
use mc_fog_ledger_server::{
    DbPollSharedState, KeyImageClientListenUri, KeyImageService, KeyImageStoreServer,
    LedgerStoreConfig,
};
use mc_fog_types::ledger::{CheckKeyImagesRequest, KeyImageQuery};
use mc_fog_uri::{KeyImageStoreScheme, KeyImageStoreUri, ConnectionUri};
use mc_ledger_db::{LedgerDB, test_utils::recreate_ledger_db};
use mc_sgx_report_cache_untrusted::ReportCacheThread;
use mc_util_grpc::{AnonymousAuthenticator};
use mc_util_metrics::{IntGauge, OpMetrics};
use mc_util_test_helper::{SeedableRng, RngType, Rng};
use mc_util_uri::{UriScheme};
use mc_watcher::watcher_db::WatcherDB;

use aes_gcm::Aes256Gcm;
use sha2::Sha512;
use tempdir::TempDir;
use url::Url;

pub fn uri_for_test(port: u16) -> KeyImageStoreUri { 
    // If a load-balancer were set up in the middle here 
    // this might need to be changed to 
    // {KeyImageStoreScheme::SCHEME_INSECURE}://localhost:1234/?responder-id={test_name}
    let name = format!("{}://localhost:{}", KeyImageStoreScheme::SCHEME_INSECURE, port); 
    KeyImageStoreUri::from_str(&name).unwrap()
}

pub struct TestingContext<R: RngCore + CryptoRng> {
    pub enclave: LedgerSgxEnclave,
    pub ledger: LedgerDB,
    pub responder_id: ResponderId,
    pub rng: R, 
    pub store_config: LedgerStoreConfig,
    pub tempdir: TempDir,
    pub tx_source_url: Url,
    pub watcher: WatcherDB,
    pub watcher_path: TempDir,
}

impl<R: RngCore + CryptoRng> TestingContext<R> {
    pub fn new(test_name: &'static str,
            logger: Logger,
            port: u16, 
            omap_capacity: u64, 
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

        let test_uri = uri_for_test(port);
        // This ID needs to match the host:port clients use in their URI when referencing the host node.
        let responder_id = test_uri.responder_id().unwrap();

        let enclave_path = std::env::current_exe()
            .expect("Could not get the path of our executable")
            // The test ends up in target/debug/deps/
            // rather than just target/debug/. So,
            // we need the parent directory.
            .parent()
            .unwrap()
            .with_file_name(ENCLAVE_FILE);

        let enclave =
            LedgerSgxEnclave::new(enclave_path, &responder_id, omap_capacity, logger.clone());

        // Make LedgerDB
        let ledger_path = test_path.join(PathBuf::from("fog_ledger"));
        let ledger = recreate_ledger_db(ledger_path.as_path());

        // Set up wallet db.
        let test_url_name = format!("http://{}.wallet.test.test", test_name);
        let url = Url::parse(&test_url_name).unwrap();

        let db_tmp = TempDir::new("wallet_db").expect("Could not make tempdir for wallet db");
        WatcherDB::create(db_tmp.path()).unwrap();
        let watcher = WatcherDB::open_rw(db_tmp.path(), &[url.clone()], logger).unwrap();

        let config = LedgerStoreConfig {
            chain_id: test_name.to_string(),
            client_responder_id: responder_id.clone(),
            client_listen_uri: test_uri.clone(),
            ledger_db: ledger_path,
            watcher_db: PathBuf::from(db_tmp.path()),
            ias_api_key: Default::default(),
            ias_spid: Default::default(),
            admin_listen_uri: Default::default(),
            client_auth_token_secret: None,
            client_auth_token_max_lifetime: Default::default(),
            omap_capacity,
        };

        Self {
            enclave,
            ledger,
            responder_id,
            rng,
            tempdir,
            tx_source_url: url,
            store_config: config,
            watcher,
            watcher_path: db_tmp,
        }
    }
}

lazy_static::lazy_static! {
    pub static ref TEST_OP_COUNTERS: OpMetrics = OpMetrics::new_and_registered("consensus_service");
}

lazy_static::lazy_static! {
    pub static ref TEST_ENCLAVE_REPORT_TIMESTAMP: IntGauge = TEST_OP_COUNTERS.gauge("enclave_report_timestamp");
}

#[test_with_logger]
pub fn simple_roundtrip(logger: Logger) {
    const TEST_NAME: &'static str = "key_image_store_simple_roundtrip";
    const PORT_START: u16 = 3223; 
    const OMAP_CAPACITY: u64 = 768; 

    let port = PORT_START;

    let rng = RngType::from_entropy(); 
    let TestingContext { 
        enclave,
        ledger,
        responder_id,
        mut rng,
        tempdir: _tempdir,
        tx_source_url: _tx_source_url,
        watcher, 
        store_config, 
        watcher_path: _watcher_path } = TestingContext::new(TEST_NAME, logger.clone(), port, OMAP_CAPACITY, rng);
 
    let shared_state = Arc::new(Mutex::new(DbPollSharedState::default()));

    let client_listen_uri = store_config.client_listen_uri.clone(); 
    let store_service = KeyImageService::new(
        KeyImageClientListenUri::Store(client_listen_uri.clone()), 
        store_config.chain_id.clone(),
        ledger,
        watcher,
        enclave.clone(), //LedgerSgxEnclave is an Arc<SgxEnclave> internally
        shared_state.clone(),
        Arc::new(AnonymousAuthenticator::default()),
        logger.clone(),
    );

    let mut store_server = KeyImageStoreServer::new_from_service(
        store_service,
        client_listen_uri.clone(),
        logger.clone(),
    );
    store_server.start();

    // Set up IAS verficiation
    // This will be a SimClient in testing contexts.
    let ias_client = AttestClient::new(&store_config.ias_api_key).expect("Could not create IAS client");
    let mut report_cache_thread = Some(ReportCacheThread::start(
        enclave.clone(),
        ias_client.clone(),
        store_config.ias_spid,
        &TEST_ENCLAVE_REPORT_TIMESTAMP,
        logger.clone(),
    ).unwrap()).unwrap();

    // Make GRPC client for sending requests.

    // Get the enclave to generate an auth request.
    let client_auth_request = enclave
        .connect_to_key_image_store(responder_id.clone())
        .unwrap();
    // Submit auth request and wait for the response.
    let (auth_response, router_to_store_session ) = enclave.router_accept(client_auth_request).unwrap(); 
    // Finish the enclave's handshake with itself.
    enclave.finish_connecting_to_key_image_store(responder_id.clone(), auth_response.into()).unwrap();
    println!("router_to_store_session is: {:?}", &router_to_store_session);

    // Generate a dummy key image we're going to check against.
    let mut test_key_image_bytes: [u8; 32] = [0u8; 32];
    rng.fill(&mut test_key_image_bytes);
    let test_key_image = KeyImageData {
        key_image: test_key_image_bytes.into(),
        block_index: 1,
        timestamp: 255,
    };
    enclave
        .add_key_image_data(vec![test_key_image.clone()])
        .unwrap();

    // Set up the client's end of the encrypted connection.
    let initiator = Start::new(responder_id.to_string());

    let init_input = ClientInitiate::<X25519, Aes256Gcm, Sha512>::default();
    let (initiator, auth_request_output) = initiator.try_next(&mut rng, init_input).unwrap();

    // Authenticate our "client" with the server.
    let auth_message = attest::AuthMessage::from(auth_request_output);
    let (client_auth_response, client_session) = enclave.client_accept(auth_message.into()).unwrap();
    println!("Initial client_session is {:?}", &client_session); 
    // We will need to double-convert, ClientAuthResponse -> AuthMessage -> AuthResponseOutput
    let auth_message = attest::AuthMessage::from(client_auth_response);
    // Initiator accepts responder's message.
    let auth_response_event = AuthResponseInput::new(auth_message.into(), Verifier::default());
    // Should be a valid noise connection at this point.
    let (mut noise_connection, _verification_report) =
        initiator.try_next(&mut rng, auth_response_event).unwrap();

    //Construct our request.
    let key_images_request = CheckKeyImagesRequest {
        queries: vec![KeyImageQuery{ 
            key_image: test_key_image.key_image.clone(), 
            start_block: 1
        }],
    };
    // Protobuf-encoded plaintext.
    let message_encoded = mc_util_serial::encode(&key_images_request);
    let ciphertext = noise_connection.encrypt(&[], &message_encoded).unwrap();
    let msg: EnclaveMessage<ClientSession> = EnclaveMessage {
        aad: vec![],
        channel_id: client_session,
        data: ciphertext,
    };

    // Decrypt and seal
    let sealed_query = enclave.decrypt_and_seal_query(msg).unwrap();
    println!("Client session on sealed_query is {:?}", &sealed_query.channel_id); 
    let mut multi_query =  enclave.create_multi_key_image_store_query_data(sealed_query).unwrap();

    let mut query: EnclaveMessage<NonceSession> = multi_query.pop().unwrap(); 
    println!("Nonce session on message is {:?}", query.channel_id); 
    // TODO: Figure out why it only works if I do this. 
    query.channel_id = router_to_store_session;

    // Get an untrusted query
    let (
        highest_processed_block_count,
        last_known_block_cumulative_txo_count,
        latest_block_version,
    ) = {
        let shared_state = shared_state.lock().expect("mutex poisoned");
        (
            shared_state.highest_processed_block_count,
            shared_state.last_known_block_cumulative_txo_count,
            shared_state.latest_block_version,
        )
    };

    let untrusted_kiqr = UntrustedKeyImageQueryResponse {
        highest_processed_block_count,
        last_known_block_cumulative_txo_count,
        latest_block_version,
        max_block_version: latest_block_version.max(*MAX_BLOCK_VERSION),
    };

    let _result = enclave.check_key_image_store(query, untrusted_kiqr.clone()).unwrap(); 

    report_cache_thread.stop().unwrap();
}
