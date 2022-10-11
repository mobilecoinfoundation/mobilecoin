// Copyright (c) 2018-2022 The MobileCoin Foundation

use grpcio::ChannelBuilder;
use mc_attest_net::{Client as AttestClient, RaClient};
use mc_attest_verifier::{MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
use mc_common::{logger::Logger, time::SystemTimeProvider, ResponderId};
use mc_fog_api::view_grpc::FogViewStoreApiClient;
use mc_fog_sql_recovery_db::{test_utils::SqlRecoveryDbTestContext, SqlRecoveryDb};
use mc_fog_test_infra::get_enclave_path;
use mc_fog_types::common::BlockRange;
use mc_fog_uri::{FogViewRouterAdminUri, FogViewRouterUri, FogViewStoreUri};
use mc_fog_view_connection::fog_view_router_client::FogViewRouterGrpcClient;
use mc_fog_view_enclave::SgxViewEnclave;
use mc_fog_view_server::{
    config::{
        ClientListenUri::Store, FogViewRouterConfig, MobileAcctViewConfig as ViewConfig,
        ShardingStrategy,
    },
    fog_view_router_server::FogViewRouterServer,
    server::ViewServer,
    sharding_strategy::EpochShardingStrategy,
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::ConnectionUri;
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, RwLock},
};

/// Contains helper methods used by the router integration test.

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
    pub fn new(omap_capacity: u64, store_count: usize, logger: Logger) -> Self {
        let port = portpicker::pick_unused_port().expect("pick_unused_port");
        let router_uri =
            FogViewRouterUri::from_str(&format!("insecure-fog-view-router://127.0.0.1:{}", port))
                .unwrap();

        let port = portpicker::pick_unused_port().expect("pick_unused_port");
        let admin_listen_uri = FogViewRouterAdminUri::from_str(&format!(
            "insecure-fog-view-router-admin://127.0.0.1:{}",
            port
        ))
        .unwrap();

        let (router_server, db_test_context, store_servers) = {
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

            let (db_test_context, store_servers, store_clients) =
                Self::create_view_stores(omap_capacity, store_count, logger.clone());

            let ra_client =
                AttestClient::new(&config.ias_api_key).expect("Could not create IAS client");
            let mut router_server =
                FogViewRouterServer::new(config, enclave, ra_client, store_clients, logger.clone());
            router_server.start();
            (router_server, db_test_context, store_servers)
        };

        let grpcio_env = Arc::new(grpcio::EnvBuilder::new().build());
        let mut mr_signer_verifier =
            MrSignerVerifier::from(mc_fog_view_enclave_measurement::sigstruct());
        mr_signer_verifier.allow_hardening_advisory("INTEL-SA-00334");

        let mut verifier = Verifier::default();
        verifier.mr_signer(mr_signer_verifier).debug(DEBUG_ENCLAVE);
        let router_client = FogViewRouterGrpcClient::new(router_uri, verifier, grpcio_env, logger);

        Self {
            db_test_context: Some(db_test_context),
            router_server: Some(router_server),
            router_client: Some(router_client),
            store_servers: Some(store_servers),
        }
    }

    /// Creates fog view stores with sane defaults.
    fn create_view_stores(
        omap_capacity: u64,
        store_count: usize,
        logger: Logger,
    ) -> (
        SqlRecoveryDbTestContext,
        Vec<ViewServer<SgxViewEnclave, AttestClient, SqlRecoveryDb, EpochShardingStrategy>>,
        Arc<RwLock<HashMap<FogViewStoreUri, Arc<FogViewStoreApiClient>>>>,
    ) {
        let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
        let mut store_servers = Vec::new();
        let mut store_clients = HashMap::new();

        for i in 0..store_count {
            let db = db_test_context.get_db_instance();
            let (store, store_uri) = {
                let port = portpicker::pick_unused_port().expect("pick_unused_port");
                let store_uri = FogViewStoreUri::from_str(&format!(
                    "insecure-fog-view-store://127.0.0.1:{}",
                    port
                ))
                .unwrap();

                // Each store is responsible for 1 block. Note that this means that the stores
                // in this test are not responsible for overlapping block ranges.
                let store_block_range = BlockRange::new(i as u64, (i + 1) as u64);
                let epoch_sharding_strategy = EpochShardingStrategy::new(store_block_range);

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

                let mut store = ViewServer::new(
                    config,
                    enclave,
                    db,
                    ra_client,
                    SystemTimeProvider::default(),
                    EpochShardingStrategy::default(),
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
