// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Tests involving activation and retiry of a three node ingest cluster

use mc_common::logger::{log, test_with_logger, Logger};
use mc_fog_ingest_server::error::IngestServiceError;
use mc_fog_ingest_server_test_utils::{get_ingress_keys, IngestServerTestHelper};
use mc_fog_recovery_db_iface::{IngestInvocationId, RecoveryDb};
use mc_ledger_db::Ledger;
use std::{thread::sleep, time::Duration};

const BASE_PORT: u16 = 4997;

// Test that a three node cluster that starts with all nodes in the idle state,
// and then one of them is activated, seems to behave corretly as we add test
// blocks. Then retire it and confirm that they all transition to idle.
// Then try to activate one of them again, and confirm that it goes immediately
// to idle because the key is retired in the DB.
#[test_with_logger]
fn three_node_cluster_activation_retiry(logger: Logger) {
    let mut helper = IngestServerTestHelper::new(BASE_PORT, logger.clone());
    helper.add_origin_block();

    // Do three repetitions of the whole thing
    for _ in 0..3 {
        let nodes = helper.make_nodes(3);
        assert!(nodes.iter().all(|n| !n.is_active()));

        // All keys should be distinct.
        let node_keys = get_ingress_keys(&nodes);
        assert_ne!(node_keys[0], node_keys[1]);
        assert_ne!(node_keys[0], node_keys[2]);
        assert_ne!(node_keys[1], node_keys[2]);

        let original_key = node_keys[0];
        nodes[0].activate().expect("node0 failed to activate");

        assert!(nodes[0].is_active());
        assert!(!nodes[1].is_active());
        assert!(!nodes[2].is_active());

        assert_eq!(
            nodes[0].get_ingress_key(),
            original_key,
            "node0 key changed after activating, unexpectedly!"
        );

        let node_keys = get_ingress_keys(&nodes);

        node_keys
            .iter()
            .for_each(|key| assert_eq!(key, &original_key));

        assert!(
            nodes[1].activate().is_err(),
            "node1 should not be able to activate"
        );
        assert!(
            nodes[2].activate().is_err(),
            "node2 should not be able to activate"
        );

        assert!(nodes[0].is_active());
        assert!(!nodes[1].is_active());
        assert!(!nodes[2].is_active());

        helper.add_test_blocks(10);
        // Wait for active node to have processed everything
        helper.wait_till_recovery_db_in_sync();

        assert!(nodes[0].is_active());
        assert!(!nodes[1].is_active());
        assert!(!nodes[2].is_active());

        nodes[0].retire().unwrap();

        assert!(
            nodes[0].is_active(),
            "Node 0 should still be in the active state, but its key is in the retiring state"
        );
        assert!(!nodes[1].is_active());
        assert!(!nodes[2].is_active());

        helper.add_test_blocks(10);
        // Wait for active node to have processed everything
        helper.wait_till_recovery_db_in_sync();

        // We now hit the pubkey expiry, so when the active node hits the next block, it
        // will switch off instead of processing it. Because it won't process
        // it, wait_for_sync won't terminate, so we just put a sleep instead.
        helper.add_test_block();
        sleep(Duration::from_secs(1));

        assert!(!nodes[0].is_active(), "First node should become inactive after it hits the pubkey expiry value after we retire the key");
        assert!(!nodes[1].is_active());
        assert!(!nodes[2].is_active());

        match nodes[0].activate() {
            Ok(_) => {
                panic!("Node 0 should not have been able to activate, the key is retired now");
            }
            Err(IngestServiceError::KeyAlreadyRetired(key)) => {
                assert_eq!(key, original_key);
            }
            Err(err) => {
                panic!("Unexpected error when trying to activate node0, should have got KeyAlreadyRetired: {}", err);
            }
        };

        match nodes[1].activate() {
            Ok(_) => {
                panic!("Node 1 should not have been able to activate, the key is retired now");
            }
            Err(IngestServiceError::KeyAlreadyRetired(key)) => {
                assert_eq!(key, original_key);
            }
            Err(err) => {
                panic!("Unexpected error when trying to activate node1, should have got KeyAlreadyRetired: {}", err);
            }
        };

        match nodes[2].activate() {
            Ok(_) => {
                panic!("Node 2 should not have been able to activate, the key is retired now");
            }
            Err(IngestServiceError::KeyAlreadyRetired(key)) => {
                assert_eq!(key, original_key);
            }
            Err(err) => {
                panic!("Unexpected error when trying to activate node2, should have got KeyAlreadyRetired: {}", err);
            }
        };

        assert!(nodes.iter().all(|n| !n.is_active()));
    }
}

// "Fencing" is a term used in k8s go leader election docu, which they say
// means, that we prevent two leaders from existing simultaneously without fail.
//
// This test has to do with, creating a situation where two leaders are active,
// and checking that the database constraint causes exactly one of them to
// become idle when they attempt to write the same block.
//
// The "activate" function does some (racy) checks by asking peers if they are
// active before we ourselves become active, in the course of creating key
// backups. In order to bypass that, we make the two nodes not peers -- the
// database doesn't care if they think they are peers or not.
#[test_with_logger]
fn three_node_cluster_fencing(logger: Logger) {
    let mut helper = IngestServerTestHelper::new(BASE_PORT, logger.clone());
    helper.add_origin_block();

    // Do three repetitions of the whole thing
    for _ in 0..3 {
        // Note: These nodes are not peers, and so do not check eachother when
        // activating
        let mut node7 = helper.make_node(7, 7..=7);
        let mut node8 = helper.make_node(8, 8..=8);
        let mut node9 = helper.make_node(9, 9..=9);

        assert!(!node7.is_active());
        assert!(!node8.is_active());
        assert!(!node9.is_active());

        let node7_key = node7.get_ingress_key();
        let node8_key = node8.get_ingress_key();
        let node9_key = node9.get_ingress_key();
        assert_ne!(node7_key, node8_key);
        assert_ne!(node7_key, node9_key);

        // Give RPC etc. time to start
        sleep(Duration::from_millis(1000));

        // This is a way to sync the ingress key of 7 to 8 and 9, without peering them
        node8.sync_keys_from_remote(&node7.peer_listen_uri).unwrap();
        node9.sync_keys_from_remote(&node7.peer_listen_uri).unwrap();

        let node7_key = node7.get_ingress_key();
        let node8_key = node8.get_ingress_key();
        let node9_key = node9.get_ingress_key();
        assert_eq!(node7_key, node8_key);
        assert_eq!(node7_key, node9_key);

        let ingress_key = node7_key;

        for _reps in 0..2 {
            // Now activate them all, which should work (without raciness) since they can't
            // see eachother, and there are no blocks yet besides origin block
            assert!(node7.activate().is_ok(), "node7 should activate");
            assert!(node8.activate().is_ok(), "node8 should activate");
            assert!(node9.activate().is_ok(), "node9 should activate");

            assert!(node7.is_active());
            assert!(node8.is_active());
            assert!(node9.is_active());

            helper.add_test_block();
            // Wait for someone to win the race
            helper.wait_till_recovery_db_in_sync();

            // Wait 1s for everyone else to realize they lost
            sleep(Duration::from_secs(1));

            let mut num_active = 0;
            let mut active_summary = None;
            if node7.is_active() {
                log::info!(logger, "node7 was active");
                num_active += 1;
                active_summary = Some(node7.get_ingest_summary());
            }
            if node8.is_active() {
                log::info!(logger, "node8 was active");
                num_active += 1;
                active_summary = Some(node8.get_ingest_summary());
            }
            if node9.is_active() {
                log::info!(logger, "node9 was active");
                num_active += 1;
                active_summary = Some(node9.get_ingest_summary());
            }

            assert_eq!(
                num_active, 1,
                "There was not only one leader when the dust settled!"
            );

            // There should be a block written only by the node that won the race.
            let active_summary = active_summary.unwrap();
            let active_iid = IngestInvocationId::from(active_summary.get_ingest_invocation_id());

            let num_blocks = helper.ledger.num_blocks().unwrap();

            let invocation_id = helper
                .recovery_db
                .get_invocation_id_by_block_and_key(ingress_key, num_blocks - 1)
                .unwrap()
                .unwrap();

            assert_eq!(active_iid, invocation_id);
        }

        // At this point we will have one active node and two inactive ones. The active
        // one won the race and the two others have lost it. We will stop the
        // active one, forcing one of the inactive ones to be the winner and by
        // that we will validate that losing the race once does not doom you to
        // always losing it or failing to write a new block. We are taking this
        // extra step since it is possible that the same node won the race in
        // all the loop iterations above, and we'd like to ensure that a node that has
        // lost the race is able to later on win it.
        let active_node_num = if node7.is_active() {
            log::info!(logger, "node7 was active");
            node7.stop();

            // Activate node 8
            assert!(
                node8.activate().is_ok(),
                "node8 should have been able to activate"
            );
            assert!(node8.is_active());
            assert!(!node9.is_active());

            8
        } else if node8.is_active() {
            log::info!(logger, "node8 was active");
            node8.stop();

            // Activate node 9
            assert!(
                node9.activate().is_ok(),
                "node9 should have been able to activate"
            );
            assert!(node9.is_active());
            assert!(!node7.is_active());

            9
        } else if node9.is_active() {
            log::info!(logger, "node9 was active");
            node9.stop();

            // Activate node 8
            assert!(
                node8.activate().is_ok(),
                "node8 should have been able to activate"
            );
            assert!(node8.is_active());
            assert!(!node7.is_active());

            8
        } else {
            panic!("no node was active");
        };

        // Write a block, the active node, that was previously inactive because it lost
        // the race, should manage to write a block.
        helper.add_test_block();
        helper.wait_till_recovery_db_in_sync();
        sleep(Duration::from_millis(100));

        let num_blocks = helper.ledger.num_blocks().unwrap();

        let node_iid = {
            let node = match active_node_num {
                8 => &node8,
                9 => &node9,
                _ => panic!("Invalid active_node_num"),
            };
            assert!(node.is_active());

            let node_summary = node.get_ingest_summary();
            assert_eq!(node_summary.get_next_block_index(), num_blocks);

            IngestInvocationId::from(node_summary.get_ingest_invocation_id())
        };

        let invocation_id = helper
            .recovery_db
            .get_invocation_id_by_block_and_key(ingress_key, num_blocks - 1)
            .unwrap();
        assert_eq!(invocation_id, Some(node_iid));
    }
}
