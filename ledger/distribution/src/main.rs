// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! A helper utility for collecting blocks from a local ledger file and storing
//! them as Protobuf-serialized files on S3.

pub mod uri;

#[cfg(test)]
mod s3_test;

use crate::uri::{canonical_region, Destination, Uri};
use aws_config::{
    meta::region::ProvideRegion, profile::ProfileFileRegionProvider, BehaviorVersion,
};
use aws_sdk_s3::{
    config::{retry::RetryConfig, timeout::TimeoutConfig, Region, StalledStreamProtectionConfig},
    primitives::ByteStream,
    types::ObjectCannedAcl,
    Client as S3Client,
};
use clap::Parser;
use mc_api::{block_num_to_s3block_path, blockchain, merged_block_num_to_s3block_path};
use mc_blockchain_types::{BlockData, BlockIndex};
use mc_common::logger::{create_app_logger, log, o, Logger};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_util_telemetry::{mark_span_as_active, start_block_span, tracer, Tracer};
use prost::Message;
use retry::{delay, retry, OperationResult};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, time::Duration};
use tokio::runtime::Handle;

/// Block writer.
pub trait BlockHandler {
    /// Write a single block.
    fn write_single_block(&mut self, block_data: &BlockData);
    /// Write multiple blocks, possibly merged.
    fn write_multiple_blocks(&mut self, blocks_data: &[BlockData]);
    /// Returns true if the `block_index` exists in the destination.
    fn block_exists(&self, block_index: BlockIndex) -> bool;

    /// Find the first missing block, assuming uploads have no gaps.
    fn first_block_to_handle(&self, num_blocks: u64) -> u64 {
        // Keep the common case of a fully uploaded ledger to one HEAD request.
        if num_blocks == 0 || self.block_exists(num_blocks - 1) {
            return num_blocks;
        }

        // Sequential uploads make existence monotonic: all blocks before the
        // first missing block exist, and all blocks after it are missing.
        let mut low = 0;
        let mut high = num_blocks - 1;
        while low < high {
            let mid = low + (high - low) / 2;
            if self.block_exists(mid) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        low
    }
}

/// Configuration for ledger distribution.
#[derive(Clone, Debug, Parser)]
#[clap(
    name = "ledger_distribution",
    about = "The MobileCoin Ledger Distribution Service."
)]
pub struct Config {
    /// Path to local LMDB db file.
    #[clap(long, env = "MC_LEDGER_PATH")]
    pub ledger_path: PathBuf,

    /// Destination to upload to.
    #[clap(long = "dest", env = "MC_DEST")]
    pub destination: Uri,

    /// Merged blocks bucket sizes. Use 0 to disable.
    #[clap(
        long,
        default_value = "100,1000,10000",
        use_value_delimiter = true,
        env = "MC_MERGE_BUCKETS"
    )]
    merge_buckets: Vec<u64>,
}

/// State file contents.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StateData {
    next_block: BlockIndex,
}

/// Resolves the region by highest-priority source
/// An empty or invalid value falls back to us-east-1
async fn resolve_region(region: Option<String>) -> Region {
    let selected = match region {
        Some(region) => Some(region),
        None => {
            match std::env::var("AWS_REGION").or_else(|_| std::env::var("AWS_DEFAULT_REGION")) {
                Ok(region) => Some(region),
                Err(_) => ProfileFileRegionProvider::new()
                    .region()
                    .await
                    .map(|region| region.as_ref().to_owned()),
            }
        }
    };
    Region::new(
        selected
            .as_deref()
            .and_then(canonical_region)
            .unwrap_or("us-east-1"),
    )
}

/// S3 block writer.
pub struct S3BlockWriter {
    bucket: String,
    prefix: PathBuf,
    s3_client: S3Client,
    logger: Logger,
}

impl S3BlockWriter {
    fn new(bucket: String, prefix: PathBuf, region: Option<String>, logger: Logger) -> Self {
        log::debug!(
            logger,
            "Creating S3 Block Writer with bucket={bucket} prefix={prefix:?} region={region:?}"
        );
        let config = Handle::current().block_on(async {
            aws_config::defaults(BehaviorVersion::v2026_01_12())
                .region(resolve_region(region).await)
                .load()
                .await
        });
        Self::from_config(
            bucket,
            prefix,
            aws_sdk_s3::config::Builder::from(&config),
            logger,
        )
    }

    fn from_config(
        bucket: String,
        prefix: PathBuf,
        config: aws_sdk_s3::config::Builder,
        logger: Logger,
    ) -> Self {
        let config = config
            // The outer retry loop already retries indefinitely with jitter.
            .retry_config(RetryConfig::disabled())
            // Bound connection setup and stalled transfers separately from the
            // generous request-to-response-header deadline.
            .timeout_config(
                TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(30))
                    // The read timeout includes sending the request body. Sampled large
                    // 10,000-block testnet archives are ~250 MB (~34 minutes at 1 Mbit/s),
                    // so allow an hour for upload and response headers.
                    .read_timeout(Duration::from_secs(60 * 60))
                    .disable_operation_timeout()
                    .disable_operation_attempt_timeout()
                    .build(),
            )
            .stalled_stream_protection(
                StalledStreamProtectionConfig::enabled()
                    .grace_period(Duration::from_secs(120))
                    .build(),
            )
            // The blocks have dots, `.`, in the names. We use path style to be
            // able to validate TLS certificates
            .force_path_style(true)
            .build();
        Self {
            bucket,
            prefix,
            s3_client: S3Client::from_conf(config),
            logger,
        }
    }

    fn write_bytes_to_s3(&self, key: &str, value: &[u8]) {
        let runtime = Handle::current();
        let result = retry(
            delay::Exponential::from_millis_with_base_factor(10).map(delay::jitter),
            || {
                runtime
                    .block_on(
                        self.s3_client
                            .put_object()
                            .bucket(&self.bucket)
                            .key(key)
                            .body(ByteStream::from(value.to_vec()))
                            .acl(ObjectCannedAcl::PublicRead)
                            .send(),
                    )
                    .map_or_else(
                        |err| {
                            log::warn!(self.logger, "Failed writing {key}: {err:?}, retrying...");
                            OperationResult::Retry(err)
                        },
                        OperationResult::Ok,
                    )
            },
        );
        result.expect("failed to write to S3");
    }
}

impl BlockHandler for S3BlockWriter {
    fn write_single_block(&mut self, block_data: &BlockData) {
        log::info!(
            self.logger,
            "S3: Handling block {}",
            block_data.block().index
        );
        let archive_block = blockchain::ArchiveBlock::from(block_data);
        let key = self
            .prefix
            .join(block_num_to_s3block_path(block_data.block().index));
        self.write_bytes_to_s3(key.to_str().unwrap(), &archive_block.encode_to_vec());
    }

    fn write_multiple_blocks(&mut self, blocks_data: &[BlockData]) {
        assert!(blocks_data.len() >= 2);
        let first_block_index = blocks_data[0].block().index;
        let last_block_index = blocks_data.last().unwrap().block().index;
        assert_eq!(
            last_block_index,
            first_block_index + blocks_data.len() as u64 - 1
        );
        log::info!(
            self.logger,
            "S3: Handling blocks {}-{}",
            first_block_index,
            last_block_index
        );
        let archive_blocks = blockchain::ArchiveBlocks::from(blocks_data);
        let key = self.prefix.join(merged_block_num_to_s3block_path(
            blocks_data.len() as u64,
            first_block_index,
        ));
        self.write_bytes_to_s3(key.to_str().unwrap(), &archive_blocks.encode_to_vec());
    }

    fn block_exists(&self, block_index: BlockIndex) -> bool {
        let runtime = Handle::current();
        let key = self.prefix.join(block_num_to_s3block_path(block_index));
        let result = retry(
            delay::Exponential::from_millis_with_base_factor(10).map(delay::jitter),
            || {
                log::info!(self.logger, "Checking for existence of block {block_index}");
                match runtime.block_on(
                    self.s3_client
                        .head_object()
                        .bucket(&self.bucket)
                        .key(key.to_str().unwrap())
                        .send(),
                ) {
                    Ok(_) => OperationResult::Ok(true),
                    Err(err)
                        if err
                            .raw_response()
                            .is_some_and(|response| response.status().as_u16() == 404) =>
                    {
                        OperationResult::Ok(false)
                    }
                    Err(err) => {
                        log::warn!(self.logger, "Failed to talk to S3 {err:?}, retrying...");
                        OperationResult::Retry(err)
                    }
                }
            },
        );
        result.expect("Stopped retrying getting block existence from S3")
    }
}

/// Local directory block writer.
pub struct LocalBlockWriter {
    path: PathBuf,
    logger: Logger,
}

impl LocalBlockWriter {
    fn new(path: PathBuf, logger: Logger) -> LocalBlockWriter {
        log::debug!(logger, "Creating Local Block Writer with path={:?}", path,);

        LocalBlockWriter { path, logger }
    }
}

impl BlockHandler for LocalBlockWriter {
    fn write_single_block(&mut self, block_data: &BlockData) {
        log::info!(
            self.logger,
            "Local: Handling block {}",
            block_data.block().index
        );

        let archive_block = blockchain::ArchiveBlock::from(block_data);

        let bytes = archive_block.encode_to_vec();

        let dest = self
            .path
            .as_path()
            .join(block_num_to_s3block_path(block_data.block().index));
        let dir = dest.as_path().parent().expect("failed getting parent");

        fs::create_dir_all(dir)
            .unwrap_or_else(|e| panic!("failed creating directory {dir:?}: {e:?}"));
        fs::write(&dest, bytes).unwrap_or_else(|err| {
            panic!(
                "failed writing block #{} to {:?}: {}",
                block_data.block().index,
                dest,
                err
            )
        });
    }

    fn write_multiple_blocks(&mut self, blocks_data: &[BlockData]) {
        assert!(blocks_data.len() >= 2);

        let first_block_index = blocks_data[0].block().index;
        let last_block_index = blocks_data.last().unwrap().block().index;
        assert_eq!(
            last_block_index,
            first_block_index + blocks_data.len() as u64 - 1
        );

        log::info!(
            self.logger,
            "Local: Handling blocks {}-{}",
            first_block_index,
            last_block_index,
        );

        let archive_blocks = blockchain::ArchiveBlocks::from(blocks_data);

        let bytes = archive_blocks.encode_to_vec();

        let dest = self.path.as_path().join(merged_block_num_to_s3block_path(
            blocks_data.len() as u64,
            first_block_index,
        ));
        let dir = dest.as_path().parent().expect("failed getting parent");

        fs::create_dir_all(dir)
            .unwrap_or_else(|e| panic!("failed creating directory {dir:?}: {e:?}"));
        fs::write(&dest, bytes).unwrap_or_else(|err| {
            panic!(
                "failed writing merged block #{first_block_index}-{last_block_index} to {dest:?}: {err}",
            )
        });
    }

    fn block_exists(&self, block_index: BlockIndex) -> bool {
        log::info!(self.logger, "Checking for existence of block {block_index}");
        let dest = self.path.join(block_num_to_s3block_path(block_index));
        dest.exists()
    }
}

// Implements the ledger db polling loop
fn main() {
    let _sentry_guard = mc_common::sentry::init();
    let (logger, _global_logger_guard) = create_app_logger(o!());
    mc_common::setup_panic_handler();

    let config = Config::parse();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let _enter_guard = runtime.enter();

    let _tracer = mc_util_telemetry::setup_default_tracer(env!("CARGO_PKG_NAME"))
        .expect("Failed setting telemetry tracer");

    // Open ledger
    log::info!(logger, "Opening ledger db {:?}", config.ledger_path);
    let ledger_db = LedgerDB::open(&config.ledger_path).expect("Could not read ledger DB");

    // Create block handler
    let mut block_handler: Box<dyn BlockHandler> = match config.destination.destination {
        Destination::S3 {
            bucket,
            prefix,
            region,
        } => Box::new(S3BlockWriter::new(bucket, prefix, region, logger.clone())),

        Destination::Local { path } => {
            fs::create_dir_all(&path)
                .unwrap_or_else(|_| panic!("Failed creating local destination directory {path:?}"));
            Box::new(LocalBlockWriter::new(path, logger.clone()))
        }
    };

    let mut next_block_num = first_block_to_handle(&ledger_db, block_handler.as_ref());

    // Poll ledger for new blocks and process them as they come.
    log::info!(
        logger,
        "Polling for blocks, starting at {next_block_num}..."
    );
    let tracer = tracer!();

    loop {
        while let Ok(block_data) = ledger_db.get_block_data(next_block_num) {
            log::trace!(logger, "Handling block #{}", next_block_num);

            let span = start_block_span(&tracer, "distribute-block", next_block_num);
            let _active_span = mark_span_as_active(span);

            tracer.in_span("write_single_block", |_cx| {
                block_handler.write_single_block(&block_data);
            });

            let cur_block_index = block_data.block().index;
            for bucket_size in config.merge_buckets.iter() {
                // Zero bucket size is invalid, bucket size of 1 is a single block.
                if *bucket_size <= 1 {
                    continue;
                }

                // Check if we just completed a bucket.
                if !(cur_block_index + 1).is_multiple_of(*bucket_size) {
                    continue;
                }

                let first_block_index = cur_block_index + 1 - *bucket_size;
                let last_block_index = cur_block_index;

                log::debug!(
                    logger,
                    "Preparing to write merged block [{}-{}]",
                    first_block_index,
                    last_block_index
                );

                let mut blocks_data = Vec::new();
                for block_index in first_block_index..=last_block_index {
                    // We panic here since this block and its associated data is expected to be in
                    // the ledger due to block_index <= next_block_num (which we
                    // successfully fetched or otherwise this code wouldn't be
                    // running).
                    let block_data = ledger_db
                        .get_block_data(block_index)
                        .unwrap_or_else(|err| panic!("failed getting block #{block_index}: {err}"));
                    blocks_data.push(block_data);
                }

                tracer.in_span("write_multiple_blocks", |_cx| {
                    block_handler.write_multiple_blocks(&blocks_data);
                });
            }

            next_block_num += 1;
        }

        // TODO: make this configurable
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn first_block_to_handle(ledger_db: &LedgerDB, block_handler: &dyn BlockHandler) -> u64 {
    let num_blocks = ledger_db
        .num_blocks()
        .expect("Failed to get the number of blocks from the ledger database");
    block_handler.first_block_to_handle(num_blocks)
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_blockchain_types::BlockVersion;
    use mc_common::logger::test_with_logger;
    use mc_ledger_db::test_utils::{create_ledger, initialize_ledger};
    use mc_transaction_core::AccountKey;
    use mc_util_test_helper::{RngType, SeedableRng};
    use std::{cell::Cell, path::Path};
    use tempfile::TempDir;
    use walkdir::WalkDir;

    #[test]
    fn resume_binary_search_handles_upload_boundaries() {
        struct ContiguousBlocks {
            uploaded: u64,
            num_blocks: u64,
            requests: Cell<u32>,
        }

        impl BlockHandler for ContiguousBlocks {
            fn write_single_block(&mut self, _: &BlockData) {
                unreachable!()
            }

            fn write_multiple_blocks(&mut self, _: &[BlockData]) {
                unreachable!()
            }

            fn block_exists(&self, index: BlockIndex) -> bool {
                assert!(index < self.num_blocks);
                self.requests.set(self.requests.get() + 1);
                index < self.uploaded
            }
        }

        // Cover every upload boundary for small ledgers, including remote-ahead
        // cases, plus u64::MAX-sized ledgers to catch arithmetic overflow.
        let cases = (0..=64)
            .flat_map(|num_blocks| (0..=num_blocks + 1).map(move |uploaded| (num_blocks, uploaded)))
            .chain([0, u64::MAX / 2, u64::MAX - 1, u64::MAX].map(|uploaded| (u64::MAX, uploaded)));
        for (num_blocks, uploaded) in cases {
            let blocks = ContiguousBlocks {
                uploaded,
                num_blocks,
                requests: Cell::new(0),
            };
            assert_eq!(
                blocks.first_block_to_handle(num_blocks),
                uploaded.min(num_blocks)
            );
            if num_blocks == 0 {
                assert_eq!(blocks.requests.get(), 0);
            } else if uploaded >= num_blocks {
                assert_eq!(blocks.requests.get(), 1);
            } else {
                // One initial check, then at most one binary-search check per
                // significant bit in num_blocks (BITS - leading_zeros).
                assert!(blocks.requests.get() <= 1 + u64::BITS - num_blocks.leading_zeros());
            }
        }
    }

    #[test]
    fn cli_parses_s3_destination() {
        let config = Config::try_parse_from([
            "ledger-distribution",
            "--ledger-path",
            "/tmp/ledger",
            "--dest",
            "s3://bucket/node.example/nested?region=EuWeSt2",
            "--merge-buckets",
            "10,100",
        ])
        .unwrap();

        assert_eq!(config.ledger_path, PathBuf::from("/tmp/ledger"));
        assert_eq!(config.merge_buckets, vec![10, 100]);
        let Destination::S3 {
            bucket,
            prefix,
            region,
        } = config.destination.destination
        else {
            panic!("expected S3");
        };
        assert_eq!(bucket, "bucket");
        assert_eq!(prefix, PathBuf::from("node.example/nested"));
        assert_eq!(region.as_deref(), Some("eu-west-2"));
    }

    #[test]
    fn invalid_explicit_region_is_reported_by_cli() {
        let error = Config::try_parse_from([
            "ledger-distribution",
            "--ledger-path",
            "/unused",
            "--dest",
            "s3://bucket/prefix?region=UNKNOWN",
            "--merge-buckets",
            "0",
        ])
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("Invalid S3 region: Not a valid AWS region: unknown"));
    }

    fn number_of_files_in_directory(directory: impl AsRef<Path>) -> u64 {
        WalkDir::new(directory)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .count()
            .try_into()
            .unwrap()
    }

    #[test_with_logger]
    fn finding_first_block_to_distribute(logger: Logger) {
        let mut rng = RngType::from_seed([0u8; 32]);
        let key = AccountKey::random(&mut rng);

        // Note: Number of blocks is one more than the block index.
        // block indices (0, 1, 2, 3, 4) => number of blocks = 5
        let number_of_blocks = 5;
        let mut ledger = create_ledger();
        initialize_ledger(
            BlockVersion::MAX,
            &mut ledger,
            number_of_blocks,
            &key,
            &mut rng,
        );

        let temp_dir = TempDir::new().unwrap();
        let distribution_path = temp_dir.path();
        let mut block_handler = LocalBlockWriter::new(distribution_path.into(), logger);

        for expected_block_count in [0, 1, 3, 5] {
            // Note: the `0` case won't write any blocks.
            // This will always re-write the blocks, but that's fine for this test.
            for block_index in 0..expected_block_count {
                block_handler.write_single_block(&ledger.get_block_data(block_index).unwrap());
            }
            assert_eq!(
                first_block_to_handle(&ledger, &block_handler),
                expected_block_count
            );
            assert_eq!(
                number_of_files_in_directory(distribution_path),
                expected_block_count
            );
        }
    }
}
