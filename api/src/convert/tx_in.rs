//! Convert to/from external::TxIn.

use crate::{convert::ConversionError, external};
use mc_transaction_core::{tx, tx::TxOutMembershipProof, InputRules};
use std::convert::TryFrom;

/// Convert tx::TxIn --> external::TxIn.
impl From<&tx::TxIn> for external::TxIn {
    fn from(source: &tx::TxIn) -> Self {
        let mut tx_in = external::TxIn::new();

        let ring: Vec<external::TxOut> = source.ring.iter().map(external::TxOut::from).collect();
        tx_in.set_ring(ring.into());

        let proofs: Vec<external::TxOutMembershipProof> = source
            .proofs
            .iter()
            .map(external::TxOutMembershipProof::from)
            .collect();
        tx_in.set_proofs(proofs.into());

        if let Some(input_rules) = source.input_rules.as_ref() {
            tx_in.set_input_rules(input_rules.into());
        }

        tx_in
    }
}

/// Convert external::TxIn --> tx::TxIn.
impl TryFrom<&external::TxIn> for tx::TxIn {
    type Error = ConversionError;

    fn try_from(source: &external::TxIn) -> Result<Self, Self::Error> {
        let mut ring: Vec<tx::TxOut> = Vec::new();
        for out in source.get_ring() {
            let tx_out = tx::TxOut::try_from(out)?;
            ring.push(tx_out);
        }

        let mut proofs: Vec<TxOutMembershipProof> = Vec::new();
        for proof in source.get_proofs() {
            let tx_proof = TxOutMembershipProof::try_from(proof)?;
            proofs.push(tx_proof);
        }

        let input_rules = source
            .input_rules
            .as_ref()
            .map(InputRules::try_from)
            .transpose()?;

        let tx_in = tx::TxIn {
            ring,
            proofs,
            input_rules,
        };
        Ok(tx_in)
    }
}

/// Convert InputRules --> external::InputRules.
impl From<&InputRules> for external::InputRules {
    fn from(source: &InputRules) -> Self {
        let mut input_rules = external::InputRules::new();

        let required_outputs: Vec<external::TxOut> = source
            .required_outputs
            .iter()
            .map(external::TxOut::from)
            .collect();
        input_rules.set_required_outputs(required_outputs.into());

        input_rules.set_max_tombstone_block(source.max_tombstone_block);

        input_rules
    }
}

/// Convert external::InputRules --> InputRules
impl TryFrom<&external::InputRules> for InputRules {
    type Error = ConversionError;

    fn try_from(source: &external::InputRules) -> Result<Self, Self::Error> {
        let required_outputs = source
            .get_required_outputs()
            .iter()
            .map(tx::TxOut::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let max_tombstone_block = source.max_tombstone_block;
        Ok(InputRules {
            required_outputs,
            max_tombstone_block,
        })
    }
}
