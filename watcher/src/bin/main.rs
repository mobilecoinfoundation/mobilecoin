// Copyright (c) 2018-2021 The MobileCoin Foundation

#![feature(external_doc)]
#![doc(include = "../../README.md")]

//! A standalone watcher program that can sync data from multiple sources.

use displaydoc::Display;
use mc_watcher::{
    config::WatcherConfig, verification_reports_collector::VerificationReportsCollector,
    watcher::Watcher, watcher_db::create_or_open_rw_watcher_db,
};

use futures::executor::block_on;
use grpcio::{EnvBuilder, ServerBuilder};
use mc_common::logger::{create_app_logger, log, o, Logger};
use mc_util_grpc::{ConnectionUriGrpcioServer, HealthCheckStatus, HealthService};
use std::{
    io::Error as IOError,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{sleep, Builder as ThreadBuilder, JoinHandle},
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

    // Start watcher sync thread.
    let mut sync_thread = WatcherSyncThread::start(watcher, config.clone(), logger.clone())
        .expect("Failed starting watcher sync thread.");

    // Start gRPC server.
    let health_check_callback: Arc<dyn Fn(&str) -> HealthCheckStatus + Sync + Send> =
        Arc::new(move |_| HealthCheckStatus::SERVING);
    let health_service =
        HealthService::new(Some(health_check_callback), logger.clone()).into_service();

    let env = Arc::new(
        EnvBuilder::new()
            .name_prefix("User-RPC".to_string())
            .build(),
    );

    let server_builder = ServerBuilder::new(env)
        .register_service(health_service)
        .bind_using_uri(&config.client_listen_uri, logger.clone());

    let mut server = server_builder.build().unwrap();
    server.start();

    for (host, port) in server.bind_addrs() {
        log::info!(logger, "gRPC API listening on {}:{}", host, port);
    }

    // Wait forever for sync thread to exit. If it ever exits, shut down the gRPC
    // server.
    sync_thread
        .join_handle
        .take()
        .expect("No join handle for watcher sync thread")
        .join()
        .expect("Failed waiting for watcher sync thread");
    block_on(server.shutdown()).expect("Could not shut down gRPC server.")
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
    pub fn start(watcher: Watcher, config: WatcherConfig, logger: Logger) -> Result<Self, Error> {
        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = stop_requested.clone();

        let join_handle = Some(ThreadBuilder::new().name("WatcherSync".to_string()).spawn(
            move || Self::thread_entrypoint(watcher, config, thread_stop_requested, logger),
        )?);

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
