// Copyright (c) 2018-2023 The MobileCoin Foundation
#![deny(missing_docs)]

//! Light client relayer entry point

use displaydoc::Display;
use mc_watcher::{
    config::WatcherConfig,
    verification_reports_collector::VerificationReportsCollector,
    watcher::{SyncResult, Watcher},
    watcher_db::create_or_open_rw_watcher_db,
};

use clap::Parser;
use futures::executor::block_on;
use grpcio::{EnvBuilder, ServerBuilder};
use mc_common::logger::{create_app_logger, log, o, Logger};
use mc_util_grpc::{ConnectionUriGrpcioServer, HealthCheckStatus, HealthService};
use mc_util_uri::ConnectionUri;
use std::{
    io::Error as IOError,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{sleep, Builder as ThreadBuilder, JoinHandle},
};

fn main() {
    fn main() {
        let _sentry_guard = mc_common::sentry::init();
        let (logger, _global_logger_guard) = create_app_logger(o!());
        mc_common::setup_panic_handler();

        let config = WatcherConfig::parse();
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

        let server_builder = ServerBuilder::new(env).register_service(health_service);

        let mut server = server_builder
            .build_using_uri(&config.client_listen_uri, logger.clone())
            .expect("Could not build server for client listen URI");
        server.start();

        log::info!(
            logger,
            "gRPC API listening on {}",
            config.client_listen_uri.addr()
        );

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
}
