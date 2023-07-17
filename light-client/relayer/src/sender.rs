// Copyright (c) 2018-2023 The MobileCoin Foundation

use std::sync::{Arc, Mutex};

use crate::BurnTx;
use mc_common::logger::{log, Logger};

// A sync which can send interesting blocks and metadata found by the relayer to
// its intended destination.
pub trait Sender {
    fn send(&mut self, burn_tx: BurnTx);
}

/// A dummy sender which just logs anything that is sent.
#[derive(Clone)]
pub struct TestSender {
    pub logger: Logger,
    pub sent: Arc<Mutex<Vec<BurnTx>>>,
}

impl Sender for TestSender {
    fn send(&mut self, burn_tx: BurnTx) {
        self.sent.lock().unwrap().push(burn_tx.clone());
        log::info!(
            self.logger,
            "Test sender: Got {} outputs and {} signatures to be sent in connection to block {}",
            burn_tx.tx_outs.len(),
            burn_tx.signatures.len(),
            burn_tx.block.index
        );
    }
}
