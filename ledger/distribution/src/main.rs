// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! A helper utility for collecting blocks from a local ledger file and storing
//! them as Protobuf-serialized files on S3.

pub mod uri;

use crate::uri::{Destination, Uri};
use clap::Parser;
use mc_api::{block_num_to_s3block_path, blockchain, merged_block_num_to_s3block_path};
use mc_blockchain_types::{BlockData, BlockIndex};
use mc_common::logger::{create_app_logger, log, o, Logger};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_util_telemetry::{mark_span_as_active, start_block_span, tracer, Tracer};
use prost::Message;
use retry::{delay, retry, OperationResult};
use rusoto_core::{request::BufferedHttpResponse, Region, RusotoError};
use rusoto_s3::{HeadObjectRequest, PutObjectRequest, S3Client, S3};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
use tokio::runtime::Handle;

/// Block writer.
pub trait BlockHandler {
    /// Write a single block.
    fn write_single_block(&mut self, block_data: &BlockData);
    /// Write multiple blocks, possibly merged.
    fn write_multiple_blocks(&mut self, blocks_data: &[BlockData]);
    /// Returns true if the `block_index` exists in the destination.
    fn block_exists(&self, block_index: BlockIndex) -> bool;
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

/// S3 block writer.
pub struct S3BlockWriter {
    path: PathBuf,
    s3_client: S3Client,
    logger: Logger,
}

impl S3BlockWriter {
    fn new(path: PathBuf, region: Region, logger: Logger) -> S3BlockWriter {
        log::debug!(
            logger,
            "Creating S3 Block Writer with path={:?} region={:?}",
            path,
            region
        );

        let s3_client = S3Client::new(region);
        S3BlockWriter {
            path,
            s3_client,
            logger,
        }
    }

    fn write_bytes_to_s3(&self, path: &str, filename: &str, value: &[u8]) {
        let runtime = Handle::current();
        let result = retry(
            delay::Exponential::from_millis_with_base_factor(10).map(delay::jitter),
            || {
                let req = PutObjectRequest {
                    bucket: path.to_string(),
                    key: filename.to_string(),
                    body: Some(value.to_vec().into()),
                    acl: Some("public-read".to_string()),
                    ..Default::default()
                };

                runtime
                    .block_on(self.s3_client.put_object(req))
                    .map_or_else(
                        |err| {
                            log::warn!(
                                self.logger,
                                "Failed writing {}: {:?}, retrying...",
                                filename,
                                err
                            );
                            OperationResult::Retry(err)
                        },
                        OperationResult::Ok,
                    )
            },
        );

        // We should always succeed since retrying should never stop until that happens.
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

        let dest = self
            .path
            .as_path()
            .join(block_num_to_s3block_path(block_data.block().index));

        let dir = dest.as_path().parent().expect("failed getting parent");
        let filename = dest.file_name().unwrap();

        self.write_bytes_to_s3(
            dir.to_str().unwrap(),
            filename.to_str().unwrap(),
            &archive_block.encode_to_vec(),
        );
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
            last_block_index,
        );

        let archive_blocks = blockchain::ArchiveBlocks::from(blocks_data);

        let dest = self.path.as_path().join(merged_block_num_to_s3block_path(
            blocks_data.len() as u64,
            first_block_index,
        ));

        let dir = dest.as_path().parent().expect("failed getting parent");
        let filename = dest.file_name().unwrap();

        self.write_bytes_to_s3(
            dir.to_str().unwrap(),
            filename.to_str().unwrap(),
            &archive_blocks.encode_to_vec(),
        );
    }

    fn block_exists(&self, block_index: BlockIndex) -> bool {
        let runtime = Handle::current();
        let result = retry(
            delay::Exponential::from_millis_with_base_factor(10).map(delay::jitter),
            || {
                let dest = self.path.join(block_num_to_s3block_path(block_index));

                let dir = dest
                    .parent()
                    .expect("failed getting parent")
                    .to_string_lossy();
                let filename = dest
                    .file_name()
                    .expect("Failed getting the file name")
                    .to_string_lossy();
                let req = HeadObjectRequest {
                    bucket: dir.into(),
                    key: filename.into(),
                    ..Default::default()
                };
                log::info!(self.logger, "Checking for existence of block {block_index}");

                let result = runtime.block_on(self.s3_client.head_object(req));
                match result {
                    Ok(_) => OperationResult::Ok(true),
                    // Happens when the object doesn't exist, see
                    // https://docs.aws.amazon.com/cli/latest/reference/s3api/head-object.html
                    Err(RusotoError::Unknown(BufferedHttpResponse { status, .. }))
                        if status.as_u16() == 404 =>
                    {
                        OperationResult::Ok(false)
                    }
                    Err(e) => {
                        log::warn!(self.logger, "Failed to talk to S3 {e:?}, retrying...");
                        OperationResult::Retry(e)
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

    let _tracer = mc_util_telemetry::setup_default_tracer(env!("CARGO_PKG_NAME"))
        .expect("Failed setting telemetry tracer");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let _enter_guard = runtime.enter();

    // Open ledger
    log::info!(logger, "Opening ledger db {:?}", config.ledger_path);
    let ledger_db = LedgerDB::open(&config.ledger_path).expect("Could not read ledger DB");

    // Create block handler
    let mut block_handler: Box<dyn BlockHandler> = match config.destination.destination {
        Destination::S3 { path, region } => {
            Box::new(S3BlockWriter::new(path, region, logger.clone()))
        }

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
                if (cur_block_index + 1) % bucket_size != 0 {
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
    let last_upload_block = (0..num_blocks)
        .rev()
        .find(|block_index| block_handler.block_exists(*block_index));
    match last_upload_block {
        Some(last_upload_block) => last_upload_block + 1,
        None => 0,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_blockchain_types::BlockVersion;
    use mc_common::logger::test_with_logger;
    use mc_ledger_db::test_utils::{create_ledger, initialize_ledger};
    use mc_transaction_core::AccountKey;
    use mc_util_test_helper::{RngType, SeedableRng};
    use std::path::Path;
    use tempfile::TempDir;
    use walkdir::WalkDir;

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
