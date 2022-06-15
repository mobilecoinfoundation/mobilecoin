// Copyright (c) 2018-2022 The MobileCoin Foundation

use assert_cmd::Command;
use mc_common::logger::{test_with_logger, Logger};
use mc_fog_ingest_server_test_utils::IngestServerTestHelper;
use predicates::prelude::*;

const BASE_PORT: u16 = 3330;

#[test_with_logger]
fn test_sync_keys_from_remote(logger: Logger) {
    let primary_helper = IngestServerTestHelper::new(BASE_PORT, logger.clone());
    let primary = primary_helper.make_node(1, 1..=1);
    primary
        .activate()
        .expect("Could not activate primary server");

    // Only shares the recovery DB with primary.
    #[allow(clippy::redundant_clone)] // not actually redundant!
    let backup_helper = IngestServerTestHelper::from_existing(
        BASE_PORT,
        None,
        primary_helper.db_test_context.clone(),
        logger.clone(),
    );
    let backup = backup_helper.make_node(3, 3..=3);

    let mut cmd = Command::cargo_bin("fog_ingest_client").unwrap();
    cmd.arg("--uri")
        .arg(backup.client_listen_uri.to_string())
        .arg("sync-keys-from-remote")
        .arg(primary.peer_listen_uri.to_string())
        .assert()
        .success()
        .stdout(predicate::str::contains(hex::encode(
            primary.get_ingress_key().as_bytes(),
        )));
}
