// Copyright (c) 2018-2023 The MobileCoin Foundation

use lazy_static::lazy_static;
use mc_common::logger::{log, Logger};
use mc_ledger_db::LedgerDB;
use prometheus::{
    histogram_opts, register_histogram, register_histogram_vec, register_int_counter, Histogram,
    HistogramVec, IntCounter,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    thread::{Builder as ThreadBuilder, JoinHandle},
    time::Duration,
};

// Initialize global metrics
lazy_static! {
    pub static ref STORE_QUERY_REQUESTS: HistogramVec = register_histogram_vec!(
        histogram_opts!(
            "fog_ledger_router_store_query_requests",
            "Queries to individual stores"
        ),
        &["store_uri", "status"]
    )
    .expect("metric cannot be created");
    pub static ref CLIENT_QUERY_RETRIES: IntCounter = register_int_counter!(
        "fog_ledger_router_bulk_query_retry",
        "Query retries per client request"
    )
    .expect("metric cannot be created");
    pub static ref ROUTER_QUERY_REQUESTS: Histogram = register_histogram!(histogram_opts!(
        "fog_ledger_router_bulk_query_requests",
        "Queries to router"
    ))
    .expect("metric cannot be created");
    pub static ref AUTH_CLIENT_REQUESTS: IntCounter = register_int_counter!(
        "fog_ledger_router_auth_client_requests",
        "Auth requests to stores"
    )
    .expect("metric cannot be created");
}

pub struct MetricsUpdateThread {
    /// Join handle used to wait for the thread to terminate.
    join_handle: Option<JoinHandle<()>>,

    /// Stop request trigger, used to signal the thread to stop.
    stop_requested: Arc<AtomicBool>,
}

/// Possible errors.
#[derive(Debug, displaydoc::Display)]
pub enum Error {
    /// IO error: {0}
    IO(std::io::Error),

    /// Thread join error
    ThreadJoin,
}

impl From<std::io::Error> for Error {
    fn from(src: std::io::Error) -> Self {
        Self::IO(src)
    }
}

impl MetricsUpdateThread {
    pub fn start(ledger_db: LedgerDB, logger: Logger) -> Result<Self, Error> {
        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = stop_requested.clone();
        let join_handle = Some(
            ThreadBuilder::new()
                .name("Ledger Metrics Updater".to_string())
                .spawn(move || Self::thread_entrypoint(ledger_db, thread_stop_requested, logger))?,
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

    fn thread_entrypoint(ledger_db: LedgerDB, stop_requested: Arc<AtomicBool>, logger: Logger) {
        log::debug!(logger, "Ledger metrics update thread started");
        loop {
            if stop_requested.load(Ordering::SeqCst) {
                log::debug!(logger, "Ledger metrics update thread stop requested.");
                break;
            }

            if let Err(e) = ledger_db.update_metrics() {
                log::error!(logger, "Error updating ledger metrics: {:?}", e);
            }

            thread::sleep(Duration::from_secs(1));
        }
    }
}

impl Drop for MetricsUpdateThread {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
