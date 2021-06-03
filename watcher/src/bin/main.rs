// Copyright (c) 2018-2021 The MobileCoin Foundation

#![feature(external_doc)]
#![doc(include = "../../README.md")]

//! A standalone watcher program that can sync data from multiple sources.

use displaydoc::Display;
use mc_watcher::{
    config::WatcherConfig, verification_reports_collector::VerificationReportsCollector,
    watcher::Watcher, watcher_db::create_or_open_rw_watcher_db,
};

use mc_common::logger::{Logger, create_app_logger, log, o};
use std::{
    io::Error as IOError,
    thread::{sleep, Builder as ThreadBuilder, JoinHandle},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use structopt::StructOpt;

fn main() {
    mc_common::setup_panic_handler();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    let config = WatcherConfig::from_args();
    let sources_config = config.sources_config();

    let watcher_db = create_or_open_rw_watcher_db(
        &config.watcher_db,
        &sources_config.tx_source_urls()[..],
        logger.clone(),
    )
    .expect("Could not create or open watcher db");
    let watcher = Watcher::new(watcher_db.clone(), config.store_block_data, logger.clone())
        .expect("Failed creating watcher");

    let _verification_reports_collector = <VerificationReportsCollector>::new(
        watcher_db,
        sources_config.sources().to_vec(),
        config.poll_interval,
        logger.clone(),
    );

    let mut sync_thread = WatcherSyncThread::start(
        watcher,
        config,
        logger.clone(),
    ).expect("Failed starting watcher sync thread.");

    sync_thread.join_handle.take()
        .expect("No join handle for watcher sync thread")
        .join()
        .expect("Failed waiting for watcher sync thread");
}

/// Possible errors.
#[derive(Debug, Display)]
pub enum Error {
    /// Thread join error
    ThreadJoin,

    /// IO error: {0}
    IO(IOError),
}

impl From<IOError> for Error {
    fn from(src: IOError) -> Self {
        Self::IO(src)
    }
}

pub struct WatcherSyncThread {
    /// Join handle used to wait for the thread to terminate.
    join_handle: Option<JoinHandle<()>>,

    /// Stop request trigger, used to signal the thread to stop.
    stop_requested: Arc<AtomicBool>,
}

impl WatcherSyncThread {
    pub fn start(
        watcher: Watcher,
        config: WatcherConfig,
        logger: Logger,
    ) -> Result<Self, Error> {
        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = stop_requested.clone();

        let join_handle = Some(ThreadBuilder::new()
            .name("WatcherSync".to_string())
            .spawn(move || {
                Self::thread_entrypoint(watcher, config, thread_stop_requested, logger)
            })?,
        );

        Ok(Self {
            join_handle,
            stop_requested,
        })

    }

    pub fn stop(&mut self) -> Result<(), Error> {
        if let Some(join_handle) = self.join_handle.take() {
            self.stop_requested.store(true, Ordering::SeqCst);
            join_handle.join().map_err(|_| Error::ThreadJoin)?;
        }

        Ok(())
    }

    fn thread_entrypoint(
        watcher: Watcher,
        config: WatcherConfig,
        stop_requested: Arc<AtomicBool>,
        logger: Logger,
    ) {
        log::debug!(logger, "Watcher sync thread started");

        loop {
            if stop_requested.load(Ordering::SeqCst) {
                log::debug!(logger, "Watcher sync thread stop requested.");
                break;
            }

            // For now, ignore origin block, as it does not have a signature.
            let syncing_done = watcher
                .sync_blocks(1, config.max_block_height)
                .expect("Could not sync signatures");
            if syncing_done {
                log::info!(logger, "sync_signatures indicates we're done");
                break;
            }

            sleep(config.poll_interval);
        }
    }
}

impl Drop for WatcherSyncThread {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
