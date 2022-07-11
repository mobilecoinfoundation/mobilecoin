// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! A helper utility for collecting blocks from a local ledger file and storing
//! them as Protobuf-serialized files on S3.

pub mod uri;

use crate::uri::{Destination, Uri};
use clap::{ArgEnum, Parser};
use mc_api::{block_num_to_s3block_path, blockchain, merged_block_num_to_s3block_path};
use mc_blockchain_types::{BlockData, BlockIndex};
use mc_common::logger::{create_app_logger, log, o, Logger};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_util_telemetry::{mark_span_as_active, start_block_span, tracer, Tracer};
use protobuf::Message;
use retry::{delay, retry, OperationResult};
use rusoto_core::Region;
use rusoto_s3::{PutObjectRequest, S3Client, S3};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
use tokio::runtime::Handle;

/// Block writer.
pub trait BlockHandler {
    /// Write a single block.
    fn write_single_block(&mut self, block_data: &BlockData);
    /// Write multiple blocks, possibly merged.
    fn write_multiple_blocks(&mut self, blocks_data: &[BlockData]);
}

/// Block to start syncing from.
#[derive(ArgEnum, Clone, Debug)]
pub enum StartFrom {
    /// Start from the origin block.
    Zero,

    /// Sync new blocks only, skipping all blocks initially in the ledger.
    Next,

    /// Start from the last block we successfully synced (stored inside a state
    /// file).
    Last,
}

/// Configuration for ledger distribution.
#[derive(Clone, Debug, Parser)]
#[clap(
    name = "ledger_distribution",
    about = "The MobileCoin Ledger Distribution Service."
)]
pub struct Config {
    /// Path to local LMDB db file.
    #[clap(long, parse(from_os_str), env = "MC_LEDGER_PATH")]
    pub ledger_path: PathBuf,

    /// Destination to upload to.
    #[clap(long = "dest", env = "MC_DEST")]
    pub destination: Uri,

    /// Block to start from.
    #[clap(arg_enum, long, default_value = "zero", env = "MC_START_FROM")]
    pub start_from: StartFrom,

    /// State file, defaults to ~/.mc-ledger-distribution-state
    #[clap(long, env = "MC_STATE_FILE")]
    pub state_file: Option<PathBuf>,

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
            delay::Exponential::from_millis(10).map(delay::jitter),
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
            &archive_block
                .write_to_bytes()
                .expect("failed to serialize ArchiveBlock"),
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
            &archive_blocks
                .write_to_bytes()
                .expect("failed to serialize ArchiveBlocks"),
        );
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

        let bytes = archive_block
            .write_to_bytes()
            .expect("failed to serialize ArchiveBlock");

        let dest = self
            .path
            .as_path()
            .join(block_num_to_s3block_path(block_data.block().index));
        let dir = dest.as_path().parent().expect("failed getting parent");

        fs::create_dir_all(dir)
            .unwrap_or_else(|e| panic!("failed creating directory {:?}: {:?}", dir, e));
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

        let bytes = archive_blocks
            .write_to_bytes()
            .expect("failed to serialize ArchiveBlock");

        let dest = self.path.as_path().join(merged_block_num_to_s3block_path(
            blocks_data.len() as u64,
            first_block_index,
        ));
        let dir = dest.as_path().parent().expect("failed getting parent");

        fs::create_dir_all(dir)
            .unwrap_or_else(|e| panic!("failed creating directory {:?}: {:?}", dir, e));
        fs::write(&dest, bytes).unwrap_or_else(|err| {
            panic!(
                "failed writing merged block #{}-{} to {:?}: {}",
                first_block_index, last_block_index, dest, err,
            )
        });
    }
}

// Implements the ledger db polling loop
fn main() {
    let config = Config::parse();

    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    let _tracer = mc_util_telemetry::setup_default_tracer(env!("CARGO_PKG_NAME"))
        .expect("Failed setting telemetry tracer");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let _enter_guard = runtime.enter();

    // Get path to our state file.
    let state_file_path = config.state_file.clone().unwrap_or_else(|| {
        let mut home_dir = dirs::home_dir().unwrap_or_else(|| panic!("Unable to get home directory, please specify state file explicitly with --state-file"));
        home_dir.push(".mc-ledger-distribution-state");
        home_dir
    });

    log::info!(logger, "State file is {:?}", state_file_path);

    // Open ledger
    log::info!(logger, "Opening ledger db {:?}", config.ledger_path);
    let ledger_db = LedgerDB::open(&config.ledger_path).expect("Could not read ledger DB");

    // Figure out the first block to sync from.
    let first_desired_block = match config.start_from {
        // Sync from the beginning of the ledger.
        StartFrom::Zero => 0,

        // Sync from the next block in the current ledger.
        StartFrom::Next => ledger_db
            .num_blocks()
            .expect("Failed getting number of blocks in ledger"),

        // Sync from the last attempted block, according to a previous state file.
        StartFrom::Last => {
            // See if the state file exists and read it if it does.
            if state_file_path.as_path().exists() {
                let file_data = fs::read_to_string(&state_file_path).unwrap_or_else(|e| {
                    panic!("Failed reading state file {:?}: {:?}", state_file_path, e)
                });
                let state_data: StateData = serde_json::from_str(&file_data).unwrap_or_else(|e| {
                    panic!("Failed parsing state file {:?}: {:?}", state_file_path, e)
                });
                state_data.next_block
            } else {
                0
            }
        }
    };

    // Create block handler
    let mut block_handler: Box<dyn BlockHandler> = match config.destination.destination {
        Destination::S3 { path, region } => {
            Box::new(S3BlockWriter::new(path, region, logger.clone()))
        }

        Destination::Local { path } => {
            fs::create_dir_all(&path).unwrap_or_else(|_| {
                panic!("Failed creating local destination directory {:?}", path)
            });
            Box::new(LocalBlockWriter::new(path, logger.clone()))
        }
    };

    // Poll ledger for new blocks and process them as they come.
    log::info!(
        logger,
        "Polling for blocks, starting at {}...",
        first_desired_block
    );
    let mut next_block_num = first_desired_block;
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
                    let block_data = ledger_db.get_block_data(block_index).unwrap_or_else(|err| {
                        panic!("failed getting block #{}: {}", block_index, err)
                    });
                    blocks_data.push(block_data);
                }

                tracer.in_span("write_multiple_blocks", |_cx| {
                    block_handler.write_multiple_blocks(&blocks_data);
                });
            }

            next_block_num += 1;

            let state = StateData {
                next_block: next_block_num,
            };
            let json_data = serde_json::to_string(&state).expect("failed serializing state data");
            fs::write(&state_file_path, json_data).expect("failed writing state file");
        }

        // TODO: make this configurable
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
