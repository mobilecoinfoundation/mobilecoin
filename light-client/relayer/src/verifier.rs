// Copyright (c) 2018-2023 The MobileCoin Foundation

use crate::RelayedBlock;
use mc_common::logger::{log, Logger};
use mc_light_client_verifier::{Error, LightClientVerifier};

pub trait Verifier {
    fn verify_burned_tx(&mut self, relayed_block: RelayedBlock) -> Result<(), Error>;
}

impl Verifier for LightClientVerifier {
    fn verify_burned_tx(&mut self, relayed_block: RelayedBlock) -> Result<(), Error> {
        self.verify_txos_in_block(
            &relayed_block.burn_tx_outs,
            &relayed_block.block,
            &relayed_block.block_contents,
            &relayed_block.signatures,
        )
    }
}

#[derive(Clone)]
pub struct TestVerifier {
    pub logger: Logger,
}

/// A test verifier which only logs burn transactions and reports success.
impl Verifier for TestVerifier {
    fn verify_burned_tx(&mut self, relayed_block: RelayedBlock) -> Result<(), Error> {
        log::info!(
            self.logger,
            "Test verifier: Got {} outputs and {} signatures to be verified in connection to block {}",
            relayed_block.burn_tx_outs.len(),
            relayed_block.signatures.len(),
            relayed_block.block.index
        );
        Ok(())
    }
}
