// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Background thread for periodically fetching data from the Gnosis API.

use crate::{error::Error, MintAuditorDb};
use mc_common::logger::{log, Logger};
use mc_ledger_db::LedgerDB;
use super::SafeId;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, sleep, JoinHandle},
    time::Duration,
};

pub struct FetcherThread {
    stop_requested: Arc<AtomicBool>,
    join_handle: Option<JoinHandle<()>>,
}

impl FetcherThread {
    pub fn start(
        safe_id: SafeId,
        mint_auditor_db: MintAuditorDb,
        ledger_db: LedgerDB,
        poll_interval: Duration,
        gnosis_api_url: String,
        logger: Logger,
    ) -> Result<Self, Error> {
        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = stop_requested.clone();
        let join_handle = Some(thread::Builder::new().name("GnosisFetcher".into()).spawn(
            move || {
                thread_entry_point(
                    thread_stop_requested,
                    safe_id,
                    mint_auditor_db,
                    ledger_db,
                    poll_interval,
                    gnosis_api_url,
                    logger,
                );
            },
        )?);

        Ok(Self {
            stop_requested,
            join_handle,
        })
    }
    pub fn stop(&mut self) {
        self.stop_requested.store(true, Ordering::Relaxed);
        if let Some(join_handle) = self.join_handle.take() {
            join_handle.join().unwrap();
        }
    }
}

impl Drop for FetcherThread {
    fn drop(&mut self) {
        self.stop();
    }
}

fn thread_entry_point(
    stop_requested: Arc<AtomicBool>,
    safe_id: SafeId,
    mint_auditor_db: MintAuditorDb,
    ledger_db: LedgerDB,
    poll_interval: Duration,
    gnosis_api_url: String,
    logger: Logger,
) {
    log::info!(logger, "GnosisFetcher thread started");
    loop {
        if stop_requested.load(Ordering::Relaxed) {
            log::info!(logger, "GnosisFetcher thread stopped");
            break;
        }

        sleep(poll_interval);
    }
}
