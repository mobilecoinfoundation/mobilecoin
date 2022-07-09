// Copyright (c) 2018-2022 The MobileCoin Foundation

//! End-to-end test of client + publisher.

mod utils;

use futures::StreamExt;
use mc_common::{
    logger::{test_with_logger, Logger},
    NodeID,
};
use mc_ledger_db::test_utils::{get_test_ledger_blocks, MockLedger};
use mc_ledger_streaming_api::{test_utils::test_node_id, Streamer};
use mc_ledger_streaming_client::{
    BackfillingStream, GrpcBlockSource, LocalBlockFetcher, QuorumSet,
};
use mc_ledger_streaming_pipeline::consensus_client;
use std::{collections::HashMap, sync::Arc};
use tempdir::TempDir;
use utils::ConsensusNode;

// Simulate 3 consensus servers, and a consensus client requiring a quorum of 2
// nodes.
#[test_with_logger]
fn local_chain(logger: Logger) {
    // Server pipelines.
    let dir = TempDir::new("local_chain").unwrap();
    let node_ids: Vec<NodeID> = (0..3).map(test_node_id).collect();
    let consensus_nodes = ConsensusNode::make_local_nodes(node_ids, dir.path(), logger.clone());

    // Build gRPC env for initiating peer connections
    let client_env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("ledger_streaming_client".to_string())
            .build(),
    );

    // Client pipeline.
    let upstreams: HashMap<NodeID, _> = consensus_nodes
        .iter()
        .map(|node| {
            (
                node.id.clone(),
                BackfillingStream::new(
                    GrpcBlockSource::new(&node.uri, client_env.clone(), logger.clone()),
                    LocalBlockFetcher::new(node.pipeline.archive_block_writer.base_path()),
                    logger.clone(),
                ),
            )
        })
        .collect();
    let quorum_set = QuorumSet::new_with_node_ids(2, upstreams.keys().cloned().collect());
    let client_pipeline =
        consensus_client(upstreams, quorum_set, MockLedger::default(), logger.clone());

    // Instantiate tokio runtime.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // Connect and drive server pipelines.
    for node in consensus_nodes {
        node.drive(
            runtime.handle(),
            0,
            get_test_ledger_blocks(100).into_iter().map(Ok),
        );
    }

    // Drive client pipeline.
    runtime.block_on(async move {
        let mut client_stream = client_pipeline.get_stream(0).unwrap();
        let mut client_height = 0;
        while let Some(result) = client_stream.next().await {
            let block_data = result.expect("unexpected client error");
            client_height = block_data.block().index + 1;
        }
        assert_eq!(client_height, 100);
    });
}
