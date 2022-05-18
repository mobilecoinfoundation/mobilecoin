// Copyright (c) 2018-2022 The MobileCoin Foundation

// These helpers are used in integration tests, but cargo still complains.

use mc_fog_ingest_server_test_utils::{IngestServerTestHelper, TestIngestNode};
use mc_fog_overseer_server::{
    server::{initialize_rocket_server, OverseerState},
    service::OverseerService,
};
use mc_fog_uri::FogIngestUri;
use rocket::local::blocking::Client;
use std::{thread::sleep, time::Duration};

pub trait TestHelperExt {
    fn enable_overseer(&self, ingest_uris: Vec<FogIngestUri>) -> Client;

    fn enable_overseer_for_nodes(&self, nodes: &[TestIngestNode]) -> Client {
        let ingest_uris = nodes
            .iter()
            .map(|node| node.client_listen_uri.clone())
            .collect();
        self.enable_overseer(ingest_uris)
    }
}

impl TestHelperExt for IngestServerTestHelper {
    fn enable_overseer(&self, ingest_uris: Vec<FogIngestUri>) -> Client {
        let mut overseer_service =
            OverseerService::new(ingest_uris, self.recovery_db.clone(), self.logger.clone());
        overseer_service
            .start()
            .expect("OverseerService failed to start");

        let overseer_state = OverseerState { overseer_service };
        let rocket_config = rocket::Config::figment()
            .merge(("port", self.base_port))
            .merge(("address", "127.0.0.1"));
        let rocket = initialize_rocket_server(rocket_config, overseer_state);
        // TODO: Consider testing the CLI instead.
        let client = Client::tracked(rocket).expect("valid rocket instance");
        client.post("/enable").dispatch();
        // Give overseer time to perform its logic.
        sleep(Duration::from_secs(10));
        client
    }
}
