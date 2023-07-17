// Copyright (c) 2018-2023 The MobileCoin Foundation

use mc_common::logger::{log, Logger};
use mc_light_client_verifier::Error;
use crate::BurnTx;

pub trait Verifier {
    fn verify_burned_tx(&mut self, burn_tx: BurnTx) -> Result<(), Error>;
}

#[derive(Clone)]
pub struct TestVerifier {
    pub logger: Logger,
}

/// A test verifier which only logs burn transactions and reports success.
impl Verifier for TestVerifier {
    fn verify_burned_tx(&mut self, burn_tx: BurnTx) -> Result<(), Error> {
        log::info!(
            self.logger,
            "Test verifier: Got {} outputs and {} signatures to be verified in connection to block {}",
            burn_tx.tx_outs.len(),
            burn_tx.signatures.len(),
            burn_tx.block.index
        );
        Ok(())
    }
}