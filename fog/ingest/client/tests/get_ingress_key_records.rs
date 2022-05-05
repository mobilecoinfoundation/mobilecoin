// Copyright (c) 2018-2022 The MobileCoin Foundation

use assert_cmd::Command;
use mc_common::logger::{test_with_logger, Logger};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_ingest_server_test_utils::{IngestServerTestHelper, TestIngestNode};
use mc_fog_recovery_db_iface::RecoveryDb;
use mc_util_from_random::FromRandom;
use predicates::prelude::*;
const BASE_PORT: u16 = 3320;

#[test_with_logger]
fn test_get_ingress_key_records(logger: Logger) {
    let data = IngestServerTest::set_up(logger);

    // Test that the command excludes retired and lost keys by default.
    let command = data.get_client_command(0, false, false);
    data.check_output(command, false, false);

    // Test that the "--include-lost" option includes active and lost keys.
    let command = data.get_client_command(0, false, true);
    data.check_output(command, false, true);

    // Test that the "--include-retired" option includes active and retired keys.
    let command = data.get_client_command(0, true, false);
    data.check_output(command, true, false);

    // Test that the "--include-lost" and "--include-retired" options
    // include active, retired, and lost keys.
    let command = data.get_client_command(0, true, true);
    data.check_output(command, true, true);

    // Test that the "--start-block-at-least" option works correctly.
    // This should exclude the retired ingress key because its start block is
    // 123.
    let command = data.get_client_command(200, true, true);
    data.check_output(command, false, true);
}

/// Contains data pertaining to the set up of the ingest server and the ingress
/// public keys.
struct IngestServerTest {
    /// The ingest server that handles incoming client requests.
    node: TestIngestNode,
    /// The hexadecimal-encoded ingest server's active ingress public key.
    active_ingress_pubkey_hex: String,
    /// A hexadecimal-encoded ingress public key that has been retired.
    retired_ingress_pubkey_hex: String,
    /// A hexadecimal-encoded ingress public key that has been lost.
    lost_ingress_pubkey_hex: String,
    /// Retain the test helper with its associated temp files.
    _helper: IngestServerTestHelper,
}

impl IngestServerTest {
    pub fn set_up(logger: Logger) -> IngestServerTest {
        // Set up a helper with an empty ledger db.
        let mut helper = IngestServerTestHelper::new(BASE_PORT, logger);
        let rng = &mut helper.rng;
        let db = &mut helper.recovery_db;

        let ingress_key1 = CompressedRistrettoPublic::from_random(rng);
        db.new_ingress_key(&ingress_key1, 123).unwrap();
        let ingress_key2 = CompressedRistrettoPublic::from_random(rng);
        db.new_ingress_key(&ingress_key2, 456).unwrap();
        let ingress_key3 = CompressedRistrettoPublic::from_random(rng);
        db.new_ingress_key(&ingress_key3, 789).unwrap();

        db.retire_ingress_key(&ingress_key1, true).unwrap();
        db.report_lost_ingress_key(ingress_key2).unwrap();

        let node = helper.make_node(42, 42..=42);

        IngestServerTest {
            node,
            _helper: helper,
            retired_ingress_pubkey_hex: hex::encode(ingress_key1.as_bytes()),
            lost_ingress_pubkey_hex: hex::encode(ingress_key2.as_bytes()),
            active_ingress_pubkey_hex: hex::encode(ingress_key3.as_bytes()),
        }
    }

    pub fn get_client_command(
        &self,
        starting_height: u64,
        include_retired: bool,
        include_lost: bool,
    ) -> Command {
        let mut cmd = Command::cargo_bin("fog_ingest_client").unwrap();
        cmd.arg("--uri")
            .arg(self.node.client_listen_uri.to_string())
            .arg("get-ingress-public-key-records")
            .arg("--start-block-at-least")
            .arg(starting_height.to_string());
        if include_retired {
            cmd.arg("--include-retired");
        }
        if include_lost {
            cmd.arg("--include-lost");
        }
        cmd
    }

    pub fn check_output(
        &self,
        mut command: Command,
        include_retired: bool,
        include_lost: bool,
    ) -> assert_cmd::assert::Assert {
        use predicate::str::contains;
        let contains_active = contains(&self.active_ingress_pubkey_hex);
        let contains_retired = contains(&self.retired_ingress_pubkey_hex);
        let contains_lost = contains(&self.lost_ingress_pubkey_hex);

        let mut assert = command.assert().success().stdout(contains_active);
        if include_retired {
            assert = assert.stdout(contains_retired);
        } else {
            assert = assert.stdout(contains_retired.not());
        }
        if include_lost {
            assert = assert.stdout(contains_lost);
        } else {
            assert = assert.stdout(contains_lost.not());
        }
        assert
    }
}
