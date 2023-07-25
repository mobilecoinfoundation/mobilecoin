// Copyright (c) 2018-2023 The MobileCoin Foundation

use std::{
    collections::BTreeMap,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
};

use mc_attest_ake::{AuthResponseInput, ClientInitiate, Start, Transition};
use mc_attest_api::attest;
use mc_attest_enclave_api::{ClientSession, EnclaveMessage, NonceSession};
use mc_attest_net::{Client as AttestClient, RaClient};
use mc_blockchain_types::MAX_BLOCK_VERSION;
use mc_common::{
    logger::{test_with_logger, Logger},
    ResponderId,
};
use mc_crypto_keys::X25519;
use mc_fog_ledger_enclave::{
    CheckKeyImagesResponse, KeyImageData, LedgerEnclave, LedgerSgxEnclave, ENCLAVE_FILE,
};
use mc_fog_ledger_enclave_api::UntrustedKeyImageQueryResponse;
use mc_fog_ledger_server::{
    sharding_strategy::EpochShardingStrategy, DbPollSharedState, KeyImageService,
    KeyImageStoreServer, LedgerStoreConfig, ShardingStrategy,
};
use mc_fog_types::ledger::{CheckKeyImagesRequest, KeyImageQuery};
use mc_fog_uri::{ConnectionUri, KeyImageStoreScheme, KeyImageStoreUri};
use mc_ledger_db::{test_utils::recreate_ledger_db, LedgerDB};
use mc_rand::{CryptoRng, RngCore};
use mc_util_grpc::AnonymousAuthenticator;
use mc_util_metrics::{IntGauge, OpMetrics};
use mc_util_test_helper::{Rng, RngType, SeedableRng};
use mc_util_uri::UriScheme;
use mc_watcher::watcher_db::WatcherDB;

use aes_gcm::Aes256Gcm;
use portpicker::pick_unused_port;
use sha2::Sha512;
use tempfile::TempDir;
use url::Url;

fn uri_for_test(port: u16) -> KeyImageStoreUri {
    // If a load-balancer were set up in the middle here
    // this might need to be changed to
    // {KeyImageStoreScheme::SCHEME_INSECURE}://localhost:1234/?
    // responder-id={test_name}
    let name = format!(
        "{}://localhost:{}",
        KeyImageStoreScheme::SCHEME_INSECURE,
        port
    );
    KeyImageStoreUri::from_str(&name)
        .expect("Could not create a URI for a key-image store test using localhost.")
}

pub struct TestingContext<R> {
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
    pub fn new(
        test_name: impl AsRef<str>,
        logger: Logger,
        port: u16,
        omap_capacity: u64,
        rng: R,
    ) -> Self {
        // Set up our directories.
        let tempdir = TempDir::new().expect("Could not produce test_ledger tempdir");
        let test_path = PathBuf::from(tempdir.path());
        let user_keys_path = test_path.join("keys");
        std::fs::create_dir_all(user_keys_path).expect("Failed creating user keys directory");

        let test_uri = uri_for_test(port);
        // This ID needs to match the host:port clients use in their URI when
        // referencing the host node.
        let responder_id = test_uri.responder_id().expect("Test URI is invalid");

        let enclave_path = std::env::current_exe()
            .expect("Could not get the path of our executable")
            // The test ends up in target/debug/deps/
            // rather than just target/debug/. So,
            // we need the parent directory.
            .parent()
            .expect("Failed to get parent of enclave path.")
            .with_file_name(ENCLAVE_FILE);

        let enclave =
            LedgerSgxEnclave::new(enclave_path, &responder_id, omap_capacity, logger.clone());

        // Make LedgerDB
        let ledger_path = test_path.join("fog_ledger");
        let ledger = recreate_ledger_db(ledger_path.as_path());

        // Set up wallet db.
        let test_url_name = format!("http://{}.wallet.test.test", test_name.as_ref());
        let url = Url::parse(&test_url_name).expect("Failed to parse test url as a Url struct.");

        let db_tmp = TempDir::new().expect("Could not make tempdir for wallet db");
        WatcherDB::create(db_tmp.path()).expect("Could not create WatcherDB.");
        let watcher = WatcherDB::open_rw(db_tmp.path(), &[url.clone()], logger)
            .expect("Failed to open WatcherDB.");

        let config = LedgerStoreConfig {
            chain_id: test_name.as_ref().to_string(),
            client_responder_id: responder_id.clone(),
            client_listen_uri: test_uri,
            ledger_db: ledger_path,
            watcher_db: PathBuf::from(db_tmp.path()),
            ias_api_key: Default::default(),
            ias_spid: Default::default(),
            admin_listen_uri: Default::default(),
            client_auth_token_secret: None,
            client_auth_token_max_lifetime: Default::default(),
            omap_capacity,
            sharding_strategy: ShardingStrategy::Epoch(EpochShardingStrategy::default()),
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
pub fn direct_key_image_store_check(logger: Logger) {
    const TEST_NAME: &str = "direct_key_image_store_check";
    const OMAP_CAPACITY: u64 = 768;

    let port = pick_unused_port().expect("No free ports");

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
        watcher_path: _watcher_path,
    } = TestingContext::new(TEST_NAME, logger.clone(), port, OMAP_CAPACITY, rng);

    let shared_state = Arc::new(Mutex::new(DbPollSharedState::default()));

    let client_listen_uri = store_config.client_listen_uri.clone();
    let store_service = KeyImageService::new(
        client_listen_uri.clone(),
        ledger,
        watcher,
        enclave.clone(), //LedgerSgxEnclave is an Arc<SgxEnclave> internally
        shared_state.clone(),
        Arc::new(AnonymousAuthenticator::default()),
        logger.clone(),
    );

    // Set up IAS verficiation
    // This will be a SimClient in testing contexts.
    let ias_client =
        AttestClient::new(&store_config.ias_api_key).expect("Could not create IAS client");
    let mut store_server = KeyImageStoreServer::new_from_service(
        store_service,
        client_listen_uri,
        enclave.clone(),
        ias_client,
        store_config.ias_spid,
        EpochShardingStrategy::default(),
        logger,
    );
    store_server.start();

    // Make GRPC client for sending requests.

    // Get the enclave to generate an auth request.
    let client_auth_request = enclave
        .ledger_store_init(responder_id.clone())
        .expect("Could not initialize ledger store on the enclave.");
    // Submit auth request and wait for the response.
    let (auth_response, _router_to_store_session) = enclave
        .frontend_accept(client_auth_request)
        .expect("frontend_accept() failed.");
    // Finish the enclave's handshake with itself.
    enclave
        .ledger_store_connect(responder_id.clone(), auth_response)
        .expect("Failed to complete the connection to a fog ledger store.");

    // Generate a dummy key image we're going to check against.
    let mut test_key_image_bytes: [u8; 32] = [0u8; 32];
    rng.fill(&mut test_key_image_bytes);
    let test_key_image = KeyImageData {
        key_image: test_key_image_bytes.try_into().unwrap(),
        block_index: 1,
        timestamp: 255,
    };
    enclave
        .add_key_image_data(vec![test_key_image])
        .expect("Error adding key image data to the enclave.");

    // Set up the client's end of the encrypted connection.
    let initiator = Start::new(responder_id.to_string());

    let init_input = ClientInitiate::<X25519, Aes256Gcm, Sha512>::default();
    let (initiator, auth_request_output) = initiator
        .try_next(&mut rng, init_input)
        .expect("Could not encrypt auth message.");

    // Authenticate our "client" with the server.
    let auth_message = attest::AuthMessage::from(auth_request_output);
    let (client_auth_response, client_session) = enclave
        .client_accept(auth_message.into())
        .expect("Unable to connect a dummy \"client\" connection to the enclave.");

    // We will need to double-convert, ClientAuthResponse -> AuthMessage ->
    // AuthResponseOutput
    let auth_message = attest::AuthMessage::from(client_auth_response);
    // Initiator accepts responder's message.
    let auth_response_event = AuthResponseInput::new(auth_message.into(), []);
    // Should be a valid noise connection at this point.
    let (mut noise_connection, _verification_report) = initiator
        .try_next(&mut rng, auth_response_event)
        .expect("Could not get a noise connection and verification report from the initiator.");

    //Construct our request.
    let key_images_request = CheckKeyImagesRequest {
        queries: vec![KeyImageQuery {
            key_image: test_key_image.key_image,
            start_block: 1,
        }],
    };
    // Protobuf-encoded plaintext.
    let message_encoded = mc_util_serial::encode(&key_images_request);
    let ciphertext = noise_connection
        .encrypt(&[], &message_encoded)
        .expect("Failed to encrypt request from the client to the router.");
    let msg: EnclaveMessage<ClientSession> = EnclaveMessage {
        aad: vec![],
        channel_id: client_session,
        data: ciphertext,
    };

    // Decrypt and seal
    let sealed_query = enclave
        .decrypt_and_seal_query(msg)
        .expect("Unable to decrypt and seal client message.");

    let mut multi_query = enclave
        .create_multi_key_image_store_query_data(sealed_query.clone())
        .expect("Could not create multi key image store query data.");

    let query = multi_query
        .pop()
        .expect("Query should have had one message");
    println!("Nonce session on message is {:?}", query.channel_id);

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

    let result = enclave
        .check_key_image_store(query, untrusted_kiqr)
        .expect("Checking key image store enclave failed.");

    let responses_btree: BTreeMap<ResponderId, EnclaveMessage<NonceSession>> =
        BTreeMap::from([(responder_id, result)]);

    let client_response = enclave
        .collate_shard_query_responses(sealed_query, responses_btree)
        .expect("Error in collate_shard_query_responses().");

    let plaintext_bytes = noise_connection
        .decrypt(&client_response.aad, &client_response.data)
        .expect("Could not decrypt response to client.");

    let done_response: CheckKeyImagesResponse =
        mc_util_serial::decode(&plaintext_bytes).expect("Failed to decode CheckKeyImagesResponse.");
    assert_eq!(done_response.results.len(), 1);

    let test_results = done_response
        .results
        .into_iter()
        .map(|result| (result.key_image, result.key_image_result_code))
        .collect::<Vec<_>>();

    // The key image result code for a spent key image is 1.
    assert_eq!(test_results, &[(test_key_image.key_image, 1)]);
}
