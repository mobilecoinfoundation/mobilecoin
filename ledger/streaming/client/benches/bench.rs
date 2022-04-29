#![feature(test)]

extern crate test;

use futures::{executor::block_on, StreamExt};
use hashbrown::HashMap;
use mc_common::logger::log;
use mc_consensus_scp::test_utils::test_node_id;
use mc_ledger_db::test_utils::get_mock_ledger;
use mc_ledger_streaming_api::{
    test_utils::{make_quorum_set, stream},
    ArchiveBlock, BlockStream, Result as StreamResult,
};
use mc_ledger_streaming_client::{
    block_validator::BlockValidator, ledger_sink::DbStream, scp_validator::SCPValidator,
    BackfillingStream, BlockchainUrl, GrpcBlockSource, HttpBlockFetcher,
};
use mc_ledger_streaming_publisher::GrpcServerSink;
use std::{env, str::FromStr, sync::Arc};
use test::Bencher;

/// Bench sinking 1000 blocks into a ledger
#[bench]
fn bench_ledger_sink_for_1000_blocks(b: &mut Bencher) {
    let logger = mc_common::logger::create_test_logger("benchmark:sink_1000_blocks".into());

    // Create simulated upstream with 1000 realistic blocks and fake ledger to sink
    // into
    let upstream_producer = stream::mock_stream_with_custom_block_contents(1, 3, 1000, 2, 0);
    let ledger = get_mock_ledger(0);

    // Initialize ledger sink stream
    let mut downstream_producer = DbStream::new(upstream_producer, ledger, true, logger.clone());

    // Benchmark stream
    b.iter(|| {
        let producer_ref = &mut downstream_producer;
        producer_ref.reinitialize_ledger(get_mock_ledger(0));
        let mut stream = producer_ref.get_block_stream(0).unwrap();
        block_on(async move { while stream.next().await.is_some() {} });
    });
}

/// Bench SCP validation on 1000 blocks
#[bench]
fn bench_scp_validation_for_1000_blocks(b: &mut Bencher) {
    let logger =
        mc_common::logger::create_test_logger("benchmark:scp_validation_1000_blocks".into());

    // Create 9 simulated upstreams with 1000 realistic blocks and simulated quorum
    // set
    let quorum_set = make_quorum_set();
    let upstream_producer = stream::mock_stream_with_custom_block_contents(1, 3, 1000, 2, 0);
    let mut upstreams = HashMap::new();
    for i in 0..9 {
        upstreams.insert(test_node_id(i), upstream_producer.clone());
    }

    // Initialize SCP validation stream
    let downstream_producer = SCPValidator::new(upstreams, logger, test_node_id(10), quorum_set);

    // Benchmark stream
    b.iter(|| {
        let stream = &mut downstream_producer.get_block_stream(0).unwrap();
        block_on(async move { while stream.next().await.is_some() {} });
    });
}

/// Bench validation of 1000 typically sized blocks
#[bench]
fn bench_validation_for_1000_blocks(b: &mut Bencher) {
    let logger = mc_common::logger::create_test_logger("benchmark:validate_1000_blocks".into());

    // Initialize upstream producer and fake ledger
    let upstream_producer = stream::mock_stream_with_custom_block_contents(1, 3, 1000, 2, 0);
    let ledger = Some(get_mock_ledger(0));

    // Initialize block validation component
    let downstream_producer = BlockValidator::new(upstream_producer, ledger, logger);

    // Benchmark stream
    b.iter(|| {
        let stream = &mut downstream_producer.get_block_stream(0).unwrap();
        block_on(async move { while stream.next().await.is_some() {} });
    });
}

/// Bench full client validation & sink pipeline
#[bench]
fn bench_integrated_components(b: &mut Bencher) {
    let logger =
        mc_common::logger::create_test_logger("benchmark:integrated_validation_1000_blocks".into());

    // Create 9 simulated upstreams with 1000 realistic blocks, simulated quorum
    // set, and fake ledger to sink into
    let quorum_set = make_quorum_set();
    let upstream_producer = stream::mock_stream_with_custom_block_contents(1, 3, 1000, 2, 0);
    let mut upstreams = HashMap::new();
    let ledger = get_mock_ledger(0);
    for i in 0..9 {
        upstreams.insert(test_node_id(i), upstream_producer.clone());
    }

    // Initialize stream chain
    let scp_validator = SCPValidator::new(upstreams, logger.clone(), test_node_id(10), quorum_set);
    let block_validator = BlockValidator::new(scp_validator, Some(ledger.clone()), logger.clone());
    let mut ledger_sink = DbStream::new(block_validator, ledger, true, logger.clone());

    // Benchmark stream chain
    b.iter(|| {
        let producer_ref = &mut ledger_sink;
        producer_ref.reinitialize_ledger(get_mock_ledger(0));
        let mut stream = producer_ref.get_block_stream(0).unwrap();
        block_on(async move { while stream.next().await.is_some() {} });
    });
}

/// Bench simulated end-end pipeline
#[bench]
fn bench_simulated_pipeline(b: &mut Bencher) {
    //Create logger and executor
    let logger =
        mc_common::logger::create_test_logger("benchmark:integrated_sink_1000_blocks".into());
    let executor = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    let mut archive_blocks: Vec<StreamResult<ArchiveBlock>> = vec![];

    // Attempt to get URL from envar data, if not stop the benchmark
    let archive_peer = if let Ok(peer) = env::var("ARCHIVE_PEER") {
        log::debug!(logger, "attempting to get real blocks from peer {:?}", peer);
        BlockchainUrl::from_str(peer.as_str()).unwrap()
    } else {
        log::warn!(
            logger,
            "A valid uri to archive blocks must be specified to perform this test"
        );
        return;
    };

    // Get real historical blocks in proto format for test data
    let fetcher = HttpBlockFetcher::new(archive_peer.clone(), logger.clone()).unwrap();
    executor.block_on(async {
        for i in 0..1000 {
            let block_url = archive_peer.block_url(i).unwrap();
            let object: StreamResult<ArchiveBlock> =
                fetcher.fetch_protobuf_object(&block_url).await;
            archive_blocks.push(object);
        }
    });

    // Create simulated upstream to be consumed by server sink
    let archive_block_stream = futures::stream::iter(archive_blocks);

    // Setup & start test server
    let sink = GrpcServerSink::new(logger.clone());
    let env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("blockstream benchmark")
            .build(),
    );
    let uri =
        mc_util_uri::ConsensusPeerUri::from_str(&format!("insecure-mcp://localhost:{}", 4242))
            .expect("Failed to parse local server URL");
    let mut server = sink
        .create_server(&uri, env.clone())
        .expect("Failed to create server");
    server.start();

    // Create client side stream chain
    let ledger = get_mock_ledger(0);
    let source = GrpcBlockSource::new(&uri, env, logger.clone());
    let backfill_stream = BackfillingStream::new(source, fetcher, logger.clone());
    let block_validator =
        BlockValidator::new(backfill_stream, Some(ledger.clone()), logger.clone());
    let mut ledger_sink = DbStream::new(block_validator, ledger, true, logger.clone());

    b.iter(|| {
        let producer_ref = &mut ledger_sink;
        producer_ref.reinitialize_ledger(get_mock_ledger(0));
        let mut stream = producer_ref.get_block_stream(0).unwrap();

        // Sink simulated blocks into server broadcast
        executor.spawn(sink.consume_protos(archive_block_stream.clone()).for_each(
            |result| async move {
                if result.is_err() {
                    println!("Error is {:?}", result);
                }
            },
        ));

        // Drive consumer stream chain
        executor.block_on(async move {
            let mut count = 0;
            while let Some(block_data) = stream.next().await {
                if count == 999 {
                    // Only unwrap block when necessary to avoid extra work in the benchmark
                    let index = block_data.unwrap().block().index;
                    if index == 999 {
                        break;
                    }
                }
                count += 1;
            }
        });
    });
}
