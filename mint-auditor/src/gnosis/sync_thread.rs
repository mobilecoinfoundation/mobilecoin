// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Background thread for periodically fetching data from the Gnosis API and
//! inserting it into the database.

use super::{sync::GnosisSync, AuditedSafeConfig};
use crate::{db::MintAuditorDb, error::Error};
use mc_common::logger::{log, Logger};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{sleep, spawn, JoinHandle},
    time::Duration,
};

/// Background thread for periodically fetching data from the Gnosis API and
/// inserting it into the database.
pub struct GnosisSyncThread {
    stop_requested: Arc<AtomicBool>,
    join_handle: Option<JoinHandle<()>>,
    logger: Logger,
}

impl GnosisSyncThread {
    /// Start the sync thread.
    pub fn start(
        audited_safe: &AuditedSafeConfig,
        mint_auditor_db: MintAuditorDb,
        poll_interval: Duration,
        logger: Logger,
    ) -> Result<Self, Error> {
        let stop_requested = Arc::new(AtomicBool::new(false));

        let thread_stop_requested = stop_requested.clone();
        let thread_logger = logger.clone();
        let thread_audited_safe = audited_safe.clone();

        let join_handle = Some(spawn(move || {
            thread_entry_point(
                thread_stop_requested,
                thread_audited_safe,
                mint_auditor_db,
                poll_interval,
                thread_logger,
            )
        }));

        Ok(Self {
            stop_requested,
            join_handle,
            logger,
        })
    }

    /// Stop the sync thread.
    pub fn stop(&mut self) {
        log::info!(self.logger, "Stopping gnosis sync thread...");
        self.stop_requested.store(true, Ordering::Relaxed);
        if let Some(join_nandle) = self.join_handle.take() {
            join_nandle
                .join()
                .expect("failed joining gnosis sync thread");
        }
    }
}

impl Drop for GnosisSyncThread {
    fn drop(&mut self) {
        self.stop();
    }
}

fn thread_entry_point(
    stop_requested: Arc<AtomicBool>,
    audited_safe: AuditedSafeConfig,
    mint_auditor_db: MintAuditorDb,
    poll_interval: Duration,
    logger: Logger,
) {
    log::info!(logger, "GnosisFetcher thread started");
    let sync = GnosisSync::new(audited_safe, mint_auditor_db, logger.clone())
        .expect("Failed creating sync object");

    loop {
        if stop_requested.load(Ordering::Relaxed) {
            log::info!(logger, "GnosisFetcher thread stop trigger received");
            break;
        }

        sync.poll();
        sleep(poll_interval);
    }
}
