use std::convert::TryFrom;

use mc_transaction_core::ring_signature::ReducedTxOut;

use crate::{external, ConversionError};

impl From<&ReducedTxOut> for external::ReducedTxOut {
    fn from(source: &ReducedTxOut) -> Self {
        let mut reduced_tx_out = external::ReducedTxOut::new();
        reduced_tx_out.set_public_key((&source.public_key).into());
        reduced_tx_out.set_target_key((&source.target_key).into());
        reduced_tx_out.set_commitment((&source.commitment).into());
        reduced_tx_out
    }
}

impl TryFrom<&external::ReducedTxOut> for ReducedTxOut {
    type Error = ConversionError;

    fn try_from(source: &external::ReducedTxOut) -> Result<Self, Self::Error> {
        Ok(ReducedTxOut {
            public_key: source.get_public_key().try_into()?,
            target_key: source.get_target_key().try_into()?,
            commitment: source.get_commitment().try_into()?,
        })
    }
}
