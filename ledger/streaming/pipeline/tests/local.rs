// Copyright (c) 2018-2022 The MobileCoin Foundation

//! End-to-end test of client + publisher.

mod utils;

use futures::StreamExt;
use mc_common::{
    logger::{log, o, test_with_logger, Logger},
    NodeID,
};
use mc_ledger_db::{create_ledger_in, test_utils::get_test_ledger_blocks};
use mc_ledger_streaming_api::{test_utils::test_node_id, Streamer};
use mc_ledger_streaming_client::{BackfillingStream, LocalBlockFetcher, QuorumSet};
use mc_ledger_streaming_pipeline::consensus_client;
use std::{collections::HashMap, sync::Arc};
use tempdir::TempDir;
use utils::ConsensusNode;

const NUM_BLOCKS: usize = 15;

// Simulate 3 consensus servers, and a consensus client requiring a quorum of
// two nodes.
#[test_with_logger]
fn local_chain(logger: Logger) {
    // Set up async runtime.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // Set up server pipelines.
    let dir = TempDir::new("local_chain").unwrap();
    let node_ids: Vec<NodeID> = (0..3).map(test_node_id).collect();
    let consensus_nodes = ConsensusNode::make_local_nodes(node_ids, dir.path(), logger.clone());
    let server_handles = consensus_nodes
        .iter()
        .map(|node| runtime.spawn(Arc::clone(node).connect(0)))
        .collect::<Vec<_>>();

    // Client pipeline.
    let client_env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("ledger_streaming_client".to_string())
            .build(),
    );
    let upstreams = consensus_nodes
        .iter()
        .map(|node| {
            (
                node.id.clone(),
                BackfillingStream::new(
                    node.grpc_client(client_env.clone()),
                    LocalBlockFetcher::new(node.pipeline.archive_block_writer.base_path()),
                    node.logger.clone(),
                ),
            )
        })
        .collect::<HashMap<_, _>>();
    // HACK: Try with 1
    let quorum_set = QuorumSet::new_with_node_ids(3, upstreams.keys().cloned().collect());
    let client_dir = TempDir::new_in("client", dir.path().to_str().unwrap()).unwrap();
    let ledger = create_ledger_in(client_dir.as_ref());
    let client_pipeline = consensus_client(
        upstreams,
        quorum_set,
        ledger,
        logger.new(o!("node" => "client")),
    );

    // Start client pipeline.
    let client_handle = runtime.spawn(async move {
        let mut client_stream = client_pipeline
            .get_stream(0)
            .expect("client pipeline stream");
        let mut client_height = 0;
        while let Some(result) = client_stream.next().await {
            let block_data = result.expect("unexpected client error");
            client_height = block_data.block().index + 1;
        }
        assert_eq!(client_height, NUM_BLOCKS as u64);
    });

    // Drive server pipelines concurrently.
    let drive_handles = consensus_nodes
        .iter()
        .map(|node| {
            let node = Arc::clone(node);
            runtime.spawn(async move {
                for block_data in get_test_ledger_blocks(NUM_BLOCKS) {
                    node.externalize_block(block_data)
                }
            })
        })
        .collect::<Vec<_>>();

    // Wait for servers to finish.
    log::debug!(&logger, "Blocking on drive handles...");
    for drive_handle in drive_handles {
        runtime.block_on(drive_handle).expect("join server driver")
    }

    log::debug!(&logger, "Blocking on server pipeline handles...");
    for server_handle in server_handles {
        runtime
            .block_on(server_handle)
            .expect("join server pipeline")
    }

    log::debug!(&logger, "Dropping simulated consensus nodes...");
    drop(consensus_nodes);

    // Wait for client driver to finish and assert.
    log::debug!(&logger, "Blocking on client pipeline handle...");
    runtime
        .block_on(client_handle)
        .expect("join client pipeline");

    log::debug!(&logger, "Success!!");
}
