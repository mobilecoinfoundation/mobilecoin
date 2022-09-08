// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::TxIn.

use crate::{external, ConversionError};
use mc_transaction_core::{tx, tx::TxOutMembershipProof, InputRules, RevealedTxOut};

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

        let required_outputs = source
            .required_outputs
            .iter()
            .map(external::TxOut::from)
            .collect();
        input_rules.set_required_outputs(required_outputs);

        input_rules.set_max_tombstone_block(source.max_tombstone_block);

        let fractional_outputs = source
            .fractional_outputs
            .iter()
            .map(external::RevealedTxOut::from)
            .collect();
        input_rules.set_fractional_outputs(fractional_outputs);

        if let Some(fractional_change) = source.fractional_change.as_ref() {
            input_rules.set_fractional_change(external::RevealedTxOut::from(fractional_change));
        }

        input_rules.set_max_allowed_change_value(source.max_allowed_change_value);

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
        let fractional_outputs = source
            .fractional_outputs
            .iter()
            .map(RevealedTxOut::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let fractional_change = source
            .fractional_change
            .as_ref()
            .map(RevealedTxOut::try_from)
            .transpose()?;
        let max_allowed_change_value = source.max_allowed_change_value;
        Ok(InputRules {
            required_outputs,
            max_tombstone_block,
            fractional_outputs,
            fractional_change,
            max_allowed_change_value,
        })
    }
}

/// Convert RevealedTxOut --> external::RevealedTxOut.
impl From<&RevealedTxOut> for external::RevealedTxOut {
    fn from(source: &RevealedTxOut) -> Self {
        let mut result = external::RevealedTxOut::new();
        result.set_tx_out(external::TxOut::from(&source.tx_out));
        result.set_amount_shared_secret(source.amount_shared_secret.to_vec());
        result
    }
}

/// Convert external::RevealedTxOut --> RevealedTxOut
impl TryFrom<&external::RevealedTxOut> for RevealedTxOut {
    type Error = ConversionError;

    fn try_from(source: &external::RevealedTxOut) -> Result<Self, Self::Error> {
        let tx_out =
            tx::TxOut::try_from(source.tx_out.as_ref().ok_or(Self::Error::ObjectMissing)?)?;
        let amount_shared_secret = source.get_amount_shared_secret().to_vec();
        Ok(RevealedTxOut {
            tx_out,
            amount_shared_secret,
        })
    }
}
