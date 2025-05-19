// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::TxPrefix.

use crate::{external, ConversionError};
use mc_transaction_core::tx;

/// Convert tx::TxPrefix --> external::TxPrefix.
impl From<&tx::TxPrefix> for external::TxPrefix {
    fn from(source: &tx::TxPrefix) -> Self {
        Self {
            inputs: source.inputs.iter().map(Into::into).collect(),
            outputs: source.outputs.iter().map(Into::into).collect(),
            fee: source.fee,
            fee_token_id: source.fee_token_id,
            tombstone_block: source.tombstone_block,
        }
    }
}

/// Convert external::TxPrefix --> tx::TxPrefix.
impl TryFrom<&external::TxPrefix> for tx::TxPrefix {
    type Error = ConversionError;

    fn try_from(source: &external::TxPrefix) -> Result<Self, Self::Error> {
        let inputs = source
            .inputs
            .iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = source
            .outputs
            .iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let tx_prefix = tx::TxPrefix {
            inputs,
            outputs,
            fee: source.fee,
            fee_token_id: source.fee_token_id,
            tombstone_block: source.tombstone_block,
        };
        Ok(tx_prefix)
    }
}
