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
use tokio::time::sleep;
use url::Url;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{channel, Sender, Receiver};

// TODO document stopping mechanism (https://tokio.rs/tokio/topics/shutdown)

pub struct FetcherThread {
    stop_requested: Arc<AtomicBool>,
    //join_handle: JoinHandle<()>,
    runtime: Runtime,
    stop_receiver: Receiver<()>,
    logger: Logger,
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
        let (stop_sender, stop_receiver) = channel(1);

        // TODO document this, remove unwrap.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        let stop_requested = Arc::new(AtomicBool::new(false));

        runtime.block_on(async {
        let join_handle = spawn(
                thread_entry_point(
                    stop_requested.clone(),
                    stop_sender,
                    safe_addr,
                    mint_auditor_db,
                    ledger_db,
                    poll_interval,
                    fetcher,
                    logger.clone(),
                )
            );
        });

        Ok(Self {
            runtime,
            stop_requested,
            stop_receiver,
            logger,
          //  join_handle,
        })
    }
    pub fn stop(&mut self) {
        log::info!(self.logger, "Stopping fetcher thread...");
        self.stop_requested.store(true, Ordering::Relaxed);
        self.runtime.block_on(async {
            let _ = self.stop_receiver.recv().await;
        });
    }
}

impl Drop for FetcherThread {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn thread_entry_point(
    stop_requested: Arc<AtomicBool>,
    _stop_sender: Sender<()>,
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
            log::info!(logger, "GnosisFetcher thread stop trigger received");
            break;
        }

        match fetcher.get_transaction_data(&safe_addr).await {
            Ok(transactions) => {
                mint_auditor_db.write_safe_txs(&transactions).expect("failed writing gnosis safe txs");
            }
            Err(err) => {
                log::error!(logger, "Failed to fetch Gnosis transactions: {}", err);
            }
        }

        sleep(poll_interval).await;
    }
}
