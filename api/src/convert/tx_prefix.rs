//! Convert to/from external::TxPrefix.

use crate::{external, ConversionError};
use mc_transaction_core::tx;

/// Convert tx::TxPrefix --> external::TxPrefix.
impl From<&tx::TxPrefix> for external::TxPrefix {
    fn from(source: &tx::TxPrefix) -> Self {
        Self {
            inputs: source.inputs.iter().map(external::TxIn::from).collect(),
            outputs: source.outputs.iter().map(external::TxOut::from).collect(),
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
        Ok(Self {
            inputs: source
                .inputs
                .iter()
                .map(tx::TxIn::try_from)
                .collect::<Result<_, _>>()?,
            outputs: source
                .outputs
                .iter()
                .map(tx::TxOut::try_from)
                .collect::<Result<_, _>>()?,
            fee: source.fee,
            fee_token_id: source.fee_token_id,
            tombstone_block: source.tombstone_block,
        })
    }
}
