#![feature(test)]

extern crate test;
use futures::{executor::block_on, StreamExt};
use hashbrown::HashMap;
use mc_consensus_scp::test_utils::test_node_id;
use mc_ledger_db::test_utils::get_mock_ledger;
use mc_ledger_streaming_api::{
    test_utils::{make_quorum_set, stream},
    BlockStream,
};
use mc_ledger_streaming_client::{
    block_validator::BlockValidator, ledger_sink::DbStream, scp_validator::SCPValidator,
};
use test::Bencher;

/// Sink 1000 blocks into a ledger
#[bench]
fn bench_ledger_sink_for_1000_blocks(b: &mut Bencher) {
    let logger = mc_common::logger::create_test_logger("benchmark:sink_1000_blocks".into());
    let upstream_producer = stream::mock_stream_with_custom_block_contents(1, 3, 1000, 2, 0);
    let ledger = get_mock_ledger(0);
    let mut downstream_producer =
        DbStream::new(upstream_producer.clone(), ledger, true, logger.clone());

    b.iter(|| {
        let producer_ref = &mut downstream_producer;
        producer_ref.reinitialize_ledger(get_mock_ledger(0));
        let mut stream = producer_ref.get_block_stream(0).unwrap();
        block_on(async move {
            while let Some(_) = stream.next().await {
                // Benchmark stream
            }
        });
    });
}

/// Do SCP validation on 1000 blocks
#[bench]
fn bench_scp_validation_for_1000_blocks(b: &mut Bencher) {
    let logger =
        mc_common::logger::create_test_logger("benchmark:scp_validation_1000_blocks".into());
    let quorum_set = make_quorum_set();
    let upstream_producer = stream::mock_stream_with_custom_block_contents(1, 3, 1000, 2, 0);
    let mut upstreams = HashMap::new();
    for i in 0..9 {
        upstreams.insert(test_node_id(i), upstream_producer.clone());
    }
    let downstream_producer = SCPValidator::new(upstreams, logger, test_node_id(10), quorum_set);

    b.iter(|| {
        let stream = &mut downstream_producer.get_block_stream(0).unwrap();
        block_on(async move {
            while let Some(_) = stream.next().await {
                // Benchmark stream
            }
        });
    });
}

/// Validate 1000 typically sized blocks
#[bench]
fn bench_validation_for_1000_blocks(b: &mut Bencher) {
    let logger = mc_common::logger::create_test_logger("benchmark:validate_1000_blocks".into());
    let upstream_producer = stream::mock_stream_with_custom_block_contents(1, 3, 1000, 2, 0);
    let ledger = Some(get_mock_ledger(0));
    let downstream_producer = BlockValidator::new(upstream_producer, ledger, logger);

    b.iter(|| {
        let stream = &mut downstream_producer.get_block_stream(0).unwrap();
        block_on(async move {
            while let Some(_) = stream.next().await {
                // Benchmark stream
            }
        });
    });
}

#[bench]
fn bench_integrated_components(b: &mut Bencher) {
    let logger =
        mc_common::logger::create_test_logger("benchmark:integrated_validation_1000_blocks".into());
    let quorum_set = make_quorum_set();
    let upstream_producer = stream::mock_stream_with_custom_block_contents(1, 3, 1000, 2, 0);
    let mut upstreams = HashMap::new();
    let ledger = get_mock_ledger(0);
    for i in 0..9 {
        upstreams.insert(test_node_id(i), upstream_producer.clone());
    }
    let scp_validator = SCPValidator::new(upstreams, logger.clone(), test_node_id(10), quorum_set);
    let block_validator = BlockValidator::new(scp_validator, Some(ledger.clone()), logger.clone());
    let mut ledger_sink = DbStream::new(block_validator, ledger, true, logger.clone());

    b.iter(|| {
        let producer_ref = &mut ledger_sink;
        producer_ref.reinitialize_ledger(get_mock_ledger(0));
        let mut stream = producer_ref.get_block_stream(0).unwrap();
        block_on(async move {
            while let Some(_) = stream.next().await {
                // Benchmark stream
            }
        });
    });
}
