// Copyright (c) 2018-2023 The MobileCoin Foundation

use crate::BurnTx;
use mc_common::logger::{log, Logger};
use mc_light_client_verifier::{Error, LightClientVerifier};

pub trait Verifier {
    fn verify_burned_tx(&mut self, burn_tx: BurnTx) -> Result<(), Error>;
}

impl Verifier for LightClientVerifier {
    fn verify_burned_tx(&mut self, burn_tx: BurnTx) -> Result<(), Error> {
        self.verify_txos_in_block(
            &burn_tx.tx_outs,
            &burn_tx.block,
            &burn_tx.block_contents,
            &burn_tx.signatures,
        )
    }
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
