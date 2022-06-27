//! Convert to/from external::TxIn.

use crate::{external, ConversionError};
use mc_transaction_core::{tx, tx::TxOutMembershipProof, InputRules};

/// Convert tx::TxIn --> external::TxIn.
impl From<&tx::TxIn> for external::TxIn {
    fn from(source: &tx::TxIn) -> Self {
        Self {
            ring: source.ring.iter().map(external::TxOut::from).collect(),
            proofs: source
                .proofs
                .iter()
                .map(external::TxOutMembershipProof::from)
                .collect(),
            input_rules: source.input_rules.as_ref().map(external::InputRules::from),
        }
    }
}

/// Convert external::TxIn --> tx::TxIn.
impl TryFrom<&external::TxIn> for tx::TxIn {
    type Error = ConversionError;

    fn try_from(source: &external::TxIn) -> Result<Self, Self::Error> {
        let ring = source
            .ring
            .iter()
            .map(tx::TxOut::try_from)
            .collect::<Result<_, _>>()?;

        let proofs = source
            .proofs
            .iter()
            .map(TxOutMembershipProof::try_from)
            .collect::<Result<_, _>>()?;

        let input_rules = source
            .input_rules
            .as_ref()
            .map(InputRules::try_from)
            .transpose()?;

        Ok(Self {
            ring,
            proofs,
            input_rules,
        })
    }
}

/// Convert InputRules --> external::InputRules.
impl From<&InputRules> for external::InputRules {
    fn from(source: &InputRules) -> Self {
        Self {
            required_outputs: source
                .required_outputs
                .iter()
                .map(external::TxOut::from)
                .collect(),
            max_tombstone_block: source.max_tombstone_block,
        }
    }
}

/// Convert external::InputRules --> InputRules
impl TryFrom<&external::InputRules> for InputRules {
    type Error = ConversionError;

    fn try_from(source: &external::InputRules) -> Result<Self, Self::Error> {
        let required_outputs = source
            .required_outputs
            .iter()
            .map(tx::TxOut::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(InputRules {
            required_outputs,
            max_tombstone_block: source.max_tombstone_block,
        })
    }
}
