// Copyright (c) 2018-2023 The MobileCoin Foundation

use std::sync::{Arc, Mutex};
use crate::RelayedBlock;
use mc_common::logger::{log, Logger};

// A sync which can send interesting blocks and metadata found by the relayer to
// its intended destination.
pub trait Sender {
    fn send(&mut self, relayed_block: RelayedBlock);
}

/// A test sender which stores and logs anything that is sent.
#[derive(Clone)]
pub struct TestSender {
    pub logger: Logger,
    pub sent: Arc<Mutex<Vec<RelayedBlock>>>,
}

impl Sender for TestSender {
    fn send(&mut self, relayed_block: RelayedBlock) {
        self.sent.lock().unwrap().push(relayed_block.clone());
        log::info!(
            self.logger,
            "Test sender: Got {} outputs and {} signatures to be sent in connection to block {}",
            relayed_block.burn_tx_outs.len(),
            relayed_block.signatures.len(),
            relayed_block.block.index
        );
    }
}
