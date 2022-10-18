// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Contains helper methods and structs used by the router integration test.

use grpcio::ChannelBuilder;
use mc_attest_net::{Client as AttestClient, RaClient};
use mc_attest_verifier::{MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
use mc_common::{logger::Logger, time::SystemTimeProvider, ResponderId};
use mc_fog_api::view_grpc::FogViewStoreApiClient;
use mc_fog_sql_recovery_db::{test_utils::SqlRecoveryDbTestContext, SqlRecoveryDb};
use mc_fog_test_infra::get_enclave_path;
use mc_fog_types::{
    common::BlockRange,
    view::{QueryResponse, TxOutSearchResult, TxOutSearchResultCode},
    ETxOutRecord,
};
use mc_fog_uri::{FogViewRouterAdminUri, FogViewRouterUri, FogViewStoreUri};
use mc_fog_view_connection::fog_view_router_client::{Error, FogViewRouterGrpcClient};
use mc_fog_view_enclave::SgxViewEnclave;
use mc_fog_view_server::{
    config::{
        ClientListenUri::Store, FogViewRouterConfig, MobileAcctViewConfig as ViewConfig,
        ShardingStrategy, ShardingStrategy::Epoch,
    },
    fog_view_router_server::FogViewRouterServer,
    server::ViewServer,
    sharding_strategy::EpochShardingStrategy,
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::ConnectionUri;
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::{Arc, RwLock},
    thread::sleep,
    time::Duration,
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
pub struct RouterTestEnvironment {
    pub router_server: Option<FogViewRouterServer<SgxViewEnclave, AttestClient>>,
    pub router_client: Option<FogViewRouterGrpcClient>,
    pub store_servers:
        Option<Vec<ViewServer<SgxViewEnclave, AttestClient, SqlRecoveryDb, EpochShardingStrategy>>>,
    pub db_test_context: Option<SqlRecoveryDbTestContext>,
}

impl RouterTestEnvironment {
    /// Creates a `RouterTestEnvironment` for the router integration tests.
    pub fn new(omap_capacity: u64, store_block_ranges: &[BlockRange], logger: Logger) -> Self {
        let (db_test_context, store_servers, store_clients) =
            Self::create_view_stores(omap_capacity, store_block_ranges, logger.clone());
        let port = portpicker::pick_unused_port().expect("pick_unused_port");
        let router_uri =
            FogViewRouterUri::from_str(&format!("insecure-fog-view-router://127.0.0.1:{}", port))
                .unwrap();
        let router_server =
            Self::create_router_server(&router_uri, omap_capacity, store_clients, &logger);
        let router_client = Self::create_router_client(router_uri, logger);
        Self {
            db_test_context: Some(db_test_context),
            router_server: Some(router_server),
            router_client: Some(router_client),
            store_servers: Some(store_servers),
        }
    }

    fn create_router_server(
        router_uri: &FogViewRouterUri,
        omap_capacity: u64,
        store_clients: Arc<RwLock<HashMap<FogViewStoreUri, Arc<FogViewStoreApiClient>>>>,
        logger: &Logger,
    ) -> FogViewRouterServer<SgxViewEnclave, AttestClient> {
        let port = portpicker::pick_unused_port().expect("pick_unused_port");
        let admin_listen_uri = FogViewRouterAdminUri::from_str(&format!(
            "insecure-fog-view-router-admin://127.0.0.1:{}",
            port
        ))
        .unwrap();
        let config = FogViewRouterConfig {
            client_responder_id: router_uri
                .responder_id()
                .expect("Could not get responder id for Fog View Router."),
            ias_api_key: Default::default(),
            ias_spid: Default::default(),
            client_listen_uri: router_uri.clone(),
            omap_capacity,
            admin_listen_uri,
        };
        let enclave = SgxViewEnclave::new(
            get_enclave_path(mc_fog_view_enclave::ENCLAVE_FILE),
            config.client_responder_id.clone(),
            config.omap_capacity,
            logger.clone(),
        );
        let ra_client =
            AttestClient::new(&config.ias_api_key).expect("Could not create IAS client");
        let mut router_server =
            FogViewRouterServer::new(config, enclave, ra_client, store_clients, logger.clone());
        router_server.start();
        router_server
    }

    fn create_router_client(
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

    /// Creates fog view stores with sane defaults.
    fn create_view_stores(
        omap_capacity: u64,
        store_block_ranges: &[BlockRange],
        logger: Logger,
    ) -> (
        SqlRecoveryDbTestContext,
        Vec<ViewServer<SgxViewEnclave, AttestClient, SqlRecoveryDb, EpochShardingStrategy>>,
        Arc<RwLock<HashMap<FogViewStoreUri, Arc<FogViewStoreApiClient>>>>,
    ) {
        let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
        let db = db_test_context.get_db_instance();
        let mut store_servers = Vec::new();
        let mut store_clients = HashMap::new();

        for (i, store_block_range) in store_block_ranges.iter().enumerate() {
            let (store, store_uri) = {
                let port = portpicker::pick_unused_port().expect("pick_unused_port");
                let store_uri = FogViewStoreUri::from_str(&format!(
                    "insecure-fog-view-store://127.0.0.1:{}",
                    port
                ))
                .unwrap();

                let epoch_sharding_strategy = EpochShardingStrategy::new(store_block_range.clone());

                let config = ViewConfig {
                    chain_id: "local".to_string(),
                    client_responder_id: ResponderId::from_str(&store_uri.addr()).unwrap(),
                    client_listen_uri: Store(store_uri.clone()),
                    client_auth_token_secret: None,
                    omap_capacity,
                    ias_spid: Default::default(),
                    ias_api_key: Default::default(),
                    admin_listen_uri: Default::default(),
                    client_auth_token_max_lifetime: Default::default(),
                    sharding_strategy: ShardingStrategy::Epoch(epoch_sharding_strategy),
                    postgres_config: Default::default(),
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
                (store, store_uri)
            };
            store_servers.push(store);

            let grpc_env = Arc::new(
                grpcio::EnvBuilder::new()
                    .name_prefix(format!("view-store-{}", i))
                    .build(),
            );
            let store_client = FogViewStoreApiClient::new(
                ChannelBuilder::default_channel_builder(grpc_env)
                    .connect_to_uri(&store_uri, &logger),
            );
            store_clients.insert(store_uri, Arc::new(store_client));
        }

        let store_clients = Arc::new(RwLock::new(store_clients));

        (db_test_context, store_servers, store_clients)
    }
}

/// Defines the drop order for each field. Do not change the order or the test
/// will hang indefinitely.
impl Drop for RouterTestEnvironment {
    fn drop(&mut self) {
        // This needs to be dropped first because failure to do so keeps the gRPC
        // connection alive and the router server will never close down.
        self.router_client = None;
        self.router_server = None;
        self.store_servers = None;
        // This needs to be dropped after the servers because they have threads that are
        // constantly checking the db.
        self.db_test_context = None;
    }
}

/// Ensure that all provided ETxOutRecords are in the enclave, and that
/// non-existing ones aren't.
pub async fn assert_e_tx_out_records(
    client: &mut FogViewRouterGrpcClient,
    records: &[ETxOutRecord],
) -> Result<QueryResponse, Error> {
    // Construct an array of expected results that includes both records we expect
    // to find and records we expect not to find.
    let mut expected_results = HashSet::new();
    for record in records {
        expected_results.insert(TxOutSearchResult {
            search_key: record.search_key.clone(),
            result_code: TxOutSearchResultCode::Found as u32,
            ciphertext: record.payload.clone(),
        });
    }

    let search_keys: Vec<_> = expected_results
        .iter()
        .map(|result| result.search_key.clone())
        .collect();

    let mut allowed_tries = 60usize;
    loop {
        let result = client.query(0, 0, search_keys.clone()).await.unwrap();

        let actual_tx_out_search_results: HashSet<TxOutSearchResult> =
            interpret_tx_out_search_results(&result.tx_out_search_results);
        if actual_tx_out_search_results == expected_results {
            return Ok(result);
        }
        if allowed_tries == 0 {
            panic!("Server did not catch up to database!");
        }
        allowed_tries -= 1;
        sleep(Duration::from_millis(1000));
    }
}

/// Takes the TxOutSearchResults and interprets the ciphertext as follows:
/// (1) The first byte is the delta between the max payload length and the
/// length of this payload.
/// (2) The rest of the bytes for that length are part of the ciphertext.
fn interpret_tx_out_search_results(results: &[TxOutSearchResult]) -> HashSet<TxOutSearchResult> {
    results
        .iter()
        .map(|result| {
            let payload_length = result.ciphertext.len() - (result.ciphertext[0] as usize);
            TxOutSearchResult {
                search_key: result.search_key.clone(),
                result_code: result.result_code,
                ciphertext: result.ciphertext[1..=payload_length].to_owned(),
            }
        })
        .collect()
}
