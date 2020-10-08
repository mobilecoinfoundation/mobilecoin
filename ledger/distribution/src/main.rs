// Copyright (c) 2018-2020 MobileCoin Inc.

//! A helper utility for collecting blocks from a local ledger file and storing them as
//! Protobuf-serialized files on S3.

pub mod uri;

use crate::uri::{Destination, Uri};
use mc_api::{block_num_to_s3block_path, blockchain};
use mc_common::logger::{create_app_logger, log, o, Logger};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::{BlockData, BlockIndex};
use protobuf::Message;
use rusoto_core::{Region, RusotoError};
use rusoto_s3::{PutObjectError, PutObjectRequest, S3Client, S3};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, str::FromStr};
use structopt::StructOpt;

pub trait BlockHandler {
    fn handle_block(&mut self, block_data: &BlockData);
}

/// Block to start syncing from.
#[derive(Clone, Debug)]
pub enum StartFrom {
    /// Start from the origin block.
    Zero,

    /// Sync new blocks only, skipping all blocks initially in the ledger.
    Next,

    /// Start from the last block we successfully synced (stored inside a state file).
    Last,
}

impl FromStr for StartFrom {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "zero" => Ok(Self::Zero),
            "next" => Ok(Self::Next),
            "last" => Ok(Self::Last),
            _ => Err("Unknown value, valid values are zero/next/last".into()),
        }
    }
}

#[derive(Clone, Debug, StructOpt)]
#[structopt(
    name = "ledger_distribution",
    about = "The MobileCoin Ledger Distribution Service."
)]
pub struct Config {
    /// Path to local LMDB db file.
    #[structopt(long, parse(from_os_str))]
    pub ledger_path: PathBuf,

    /// Destination to upload to.
    #[structopt(long = "dest")]
    pub destination: Uri,

    /// Block to start from.
    #[structopt(long, default_value = "zero")]
    pub start_from: StartFrom,

    /// State file, defaults to ~/.mc-ledger-distribution-state
    #[structopt(long)]
    pub state_file: Option<PathBuf>,
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
        let result: Result<
            retry::OperationResult<(), ()>,
            retry::Error<retry::OperationResult<(), RusotoError<PutObjectError>>>,
        > = retry::retry(
            retry::delay::Exponential::from_millis(10).map(retry::delay::jitter),
            || {
                let req = PutObjectRequest {
                    bucket: path.to_string(),
                    key: String::from(filename),
                    body: Some(value.to_vec().into()),
                    acl: Some("public-read".to_string()),
                    ..Default::default()
                };

                self.s3_client
                    .put_object(req)
                    .sync()
                    .map(|_| retry::OperationResult::Ok(()))
                    .map_err(|err: RusotoError<PutObjectError>| {
                        log::warn!(
                            self.logger,
                            "Failed writing {}: {:?}, retrying...",
                            filename,
                            err
                        );
                        retry::OperationResult::Retry(err)
                    })
            },
        );

        // We should always succeed since retrying should never stop until that happens.
        assert!(result.is_ok());
    }
}

impl BlockHandler for S3BlockWriter {
    fn handle_block(&mut self, block_data: &BlockData) {
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
    fn handle_block(&mut self, block_data: &BlockData) {
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
        fs::write(&dest, bytes).unwrap_or_else(|_| {
            panic!(
                "failed writing block #{} to {:?}",
                block_data.block().index,
                dest
            )
        });
    }
}

// Implements the ledger db polling loop
fn main() {
    let config = Config::from_args();

    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    // Get path to our state file.
    let state_file_path = config.state_file.clone().unwrap_or_else(|| {
        let mut home_dir = dirs::home_dir().unwrap_or_else(|| panic!("Unable to get home directory, please specify state file explicitly with --state-file"));
        home_dir.push(".mc-ledger-distribution-state");
        home_dir
    });

    log::info!(logger, "State file is {:?}", state_file_path);

    // Open ledger
    log::info!(logger, "Opening ledger db {:?}", config.ledger_path);
    let ledger_db = LedgerDB::open(config.ledger_path.clone()).expect("Could not read ledger DB");

    // Figure out the first block to sync from.
    let first_desired_block = match config.start_from {
        StartFrom::Zero => 0,
        StartFrom::Next => {
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
        StartFrom::Last => ledger_db
            .num_blocks()
            .expect("Failed getting number of blocks in ledger"),
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
    loop {
        while let Ok(block_data) = ledger_db.get_block_data(next_block_num) {
            log::trace!(logger, "Handling block #{}", next_block_num);

            block_handler.handle_block(&block_data);
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
