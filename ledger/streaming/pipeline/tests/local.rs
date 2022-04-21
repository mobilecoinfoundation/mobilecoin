// Copyright (c) 2018-2022 The MobileCoin Foundation

//! End-to-end test of client + publisher.

mod utils;

use futures::{executor::block_on, StreamExt};
use mc_common::{
    logger::{test_with_logger, Logger},
    NodeID,
};
use mc_ledger_db::test_utils::MockLedger;
use mc_ledger_streaming_api::{test_utils::test_node_id, Streamer};
use mc_ledger_streaming_client::{LocalBlockFetcher, QuorumSet};
use mc_ledger_streaming_pipeline::consensus_client;
use std::sync::Arc;
use tempdir::TempDir;
use utils::{get_uris_by_node_id, ConsensusNode};

// Simulate 3 consensus servers, and a consensus client requiring a quorum of 2
// nodes.
#[test_with_logger]
fn local_chain(logger: Logger) {
    let dir = TempDir::new("local_chain").unwrap();

    let node_ids: Vec<NodeID> = (0..3).map(test_node_id).collect();
    let consensus_nodes = ConsensusNode::make_local_nodes(node_ids, 0, dir.path(), logger.clone());
    let grpc_uris = get_uris_by_node_id(&consensus_nodes[..]);
    let quorum_set = QuorumSet::new_with_node_ids(2, grpc_uris.keys().cloned().collect());

    // Build gRPC env for initiating peer connections
    let client_env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("ledger_streaming_client".to_string())
            .build(),
    );
    let fetcher = LocalBlockFetcher::new(dir.path());
    let ledger = MockLedger::default();
    let client_pipeline = consensus_client(
        grpc_uris,
        quorum_set,
        client_env,
        fetcher,
        ledger,
        logger.clone(),
    );
    let mut client_stream = client_pipeline.get_stream(0).unwrap();

    // TODO: Connect and drive server pipeline.
    block_on(async move {
        let mut client_height = 0;
        while let Some(result) = client_stream.next().await {
            let block_data = result.expect("unexpected error");
            client_height = block_data.block().index + 1;
        }
        assert_eq!(client_height, 100);
    })
}
