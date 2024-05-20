// Copyright (c) 2018-2024 The MobileCoin Foundation

//! Code for periodically submitting any queued data we have into T3.

use crate::database::Database;
use mc_common::logger::{log, Logger};
use mc_t3_api::T3Uri;
use mc_t3_connection::T3Connection;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

/// Maximum number of TransparentTransaction objects to submit to T3 in a single
/// poll loop iteration.
const MAX_TRANSPARENT_TRANSACTIONS_PER_POLL: usize = 10;

/// T3 Sync Thread - holds objects needed to cleanly terminate the sync thread.
pub struct T3SyncThread {
    /// The main sync thread handle.
    join_handle: Option<thread::JoinHandle<()>>,

    /// Stop trigger, used to signal the thread to reminate.
    stop_requested: Arc<AtomicBool>,
}

impl T3SyncThread {
    pub fn start(
        mobilecoind_db: Database,
        t3_uri: T3Uri,
        t3_api_key: String,
        sync_interval: Duration,
        logger: Logger,
    ) -> Self {
        let stop_requested = Arc::new(AtomicBool::new(false));

        let thread_stop_requested = stop_requested.clone();
        let join_handle = thread::spawn(move || {
            t3_sync_thread_entry_point(
                mobilecoind_db,
                t3_uri,
                t3_api_key,
                sync_interval,
                thread_stop_requested,
                logger,
            );
        });

        Self {
            join_handle: Some(join_handle),
            stop_requested,
        }
    }

    pub fn stop(&mut self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        if let Some(join_handle) = self.join_handle.take() {
            join_handle.join().expect("T3SyncThread join failed");
        }
    }
}

impl Drop for T3SyncThread {
    fn drop(&mut self) {
        self.stop();
    }
}

fn t3_sync_thread_entry_point(
    mobilecoind_db: Database,
    t3_uri: T3Uri,
    t3_api_key: String,
    sync_interval: Duration,
    stop_requested: Arc<AtomicBool>,
    logger: Logger,
) {
    log::info!(logger, "T3 Sync thread started");

    let t3_conn = T3Connection::new(&t3_uri, t3_api_key, logger.clone());

    loop {
        if stop_requested.load(Ordering::SeqCst) {
            break;
        }

        for _ in 0..MAX_TRANSPARENT_TRANSACTIONS_PER_POLL {
            match mobilecoind_db.dequeue_transparent_tx() {
                Ok(None) => {
                    break;
                }

                Ok(Some((ttx_index, ttx))) => match t3_conn.create_transaction(ttx.clone()) {
                    Ok(_) => {
                        log::info!(
                            logger,
                            "Successfully submitted transparent transaction {} to T3",
                            ttx.public_key_hex
                        );

                        if let Err(err) = mobilecoind_db.remove_transparent_tx(ttx_index) {
                            log::error!(
                                logger,
                                "Error removing transparent transaction {} from queue: {:?}",
                                ttx.public_key_hex,
                                err
                            );
                            break;
                        }
                    }
                    Err(err) => {
                        log::error!(
                            logger,
                            "Error submitting transparent transaction {} to T3: {:?}",
                            ttx.public_key_hex,
                            err
                        );
                        break;
                    }
                },

                Err(err) => {
                    log::error!(logger, "Error dequeuing transparent transaction: {:?}", err);
                    break;
                }
            }
        }

        thread::sleep(sync_interval);
    }
}
