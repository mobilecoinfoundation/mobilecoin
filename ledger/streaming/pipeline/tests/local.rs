// Copyright (c) 2018-2022 The MobileCoin Foundation

//! End-to-end test of client + publisher.

mod utils;

use futures::StreamExt;
use mc_common::{
    logger::{o, test_with_logger, Logger},
    NodeID,
};
use mc_ledger_db::{create_ledger_in, test_utils::get_test_ledger_blocks};
use mc_ledger_streaming_api::{test_utils::test_node_id, Streamer};
use mc_ledger_streaming_client::{
    BackfillingStream, GrpcBlockSource, LocalBlockFetcher, QuorumSet,
};
use mc_ledger_streaming_pipeline::consensus_client;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tempdir::TempDir;
use utils::ConsensusNode;

// Simulate 3 consensus servers, and a consensus client requiring a quorum of
// two nodes.
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
    let upstreams = consensus_nodes
        .iter()
        .map(|node| {
            (
                node.id.clone(),
                BackfillingStream::new(
                    GrpcBlockSource::new(&node.uri, client_env.clone(), node.logger.clone()),
                    LocalBlockFetcher::new(node.pipeline.archive_block_writer.base_path()),
                    node.logger.clone(),
                ),
            )
        })
        .collect::<HashMap<_, _>>();
    // HACK: Try with 1
    let quorum_set = QuorumSet::new_with_node_ids(1, upstreams.keys().cloned().collect());
    let client_dir = TempDir::new_in("client", dir.path().to_str().unwrap()).unwrap();
    let ledger = create_ledger_in(client_dir.as_ref());
    let client_pipeline = consensus_client(
        upstreams,
        quorum_set,
        ledger,
        logger.new(o!("node" => "client")),
    );

    // Instantiate tokio runtime.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // Connect and drive server pipelines.
    for node in consensus_nodes {
        node.add_many(
            runtime.handle(),
            0,
            get_test_ledger_blocks(100).into_iter().map(Ok),
        );
    }

    // Drive client pipeline.
    runtime.block_on(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut client_stream = client_pipeline.get_stream(0).unwrap();
        let mut client_height = 0;
        while let Some(result) = client_stream.next().await {
            let block_data = result.expect("unexpected client error");
            client_height = block_data.block().index + 1;
        }
        assert_eq!(client_height, 100);
    });
}
