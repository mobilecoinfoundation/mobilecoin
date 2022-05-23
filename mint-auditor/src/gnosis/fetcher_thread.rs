// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Background thread for periodically fetching data from the Gnosis API.

use super::{fetcher::GnosisSafeFetcher, SafeAddr};
use crate::{error::Error, MintAuditorDb};
use mc_common::logger::{log, Logger};
use mc_ledger_db::LedgerDB;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::task::{spawn, JoinHandle};
use url::Url;

pub struct FetcherThread {
    stop_requested: Arc<AtomicBool>,
    join_handle: Option<JoinHandle<()>>,
}

impl FetcherThread {
    pub fn start(
        safe_addr: SafeAddr,
        mint_auditor_db: MintAuditorDb,
        ledger_db: LedgerDB,
        poll_interval: Duration,
        gnosis_api_url: Url,
        logger: Logger,
    ) -> Result<Self, Error> {
        let fetcher = GnosisSafeFetcher::new(gnosis_api_url, logger.clone())?;

        // TODO document this, remove unwrap.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = stop_requested.clone();


        let join_handle = spawn(
            move || async {
                thread_entry_point(
                    thread_stop_requested,
                    safe_addr,
                    mint_auditor_db,
                    ledger_db,
                    poll_interval,
                    fetcher,
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

async fn thread_entry_point(
    stop_requested: Arc<AtomicBool>,
    safe_addr: SafeAddr,
    mint_auditor_db: MintAuditorDb,
    ledger_db: LedgerDB,
    poll_interval: Duration,
    fetcher: GnosisSafeFetcher,
    logger: Logger,
) {
    log::info!(logger, "GnosisFetcher thread started");
    loop {
        if stop_requested.load(Ordering::Relaxed) {
            log::info!(logger, "GnosisFetcher thread stopped");
            break;
        }

        match await fetcher.get_transaction_data(safe_addr) {
            Ok(transactions) => {
                println!("{:?}", transactions);
            }
            Err(err) => {
                log::error!(logger, "Failed to fetch Gnosis transactions: {}", err);
            }
        }

        sleep(poll_interval);
    }
}
