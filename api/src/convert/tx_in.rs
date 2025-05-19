// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::TxIn.

use crate::{external, ConversionError};
use mc_transaction_core::{tx, InputRules, RevealedTxOut};

/// Convert tx::TxIn --> external::TxIn.
impl From<&tx::TxIn> for external::TxIn {
    fn from(source: &tx::TxIn) -> Self {
        Self {
            ring: source.ring.iter().map(Into::into).collect(),
            proofs: source.proofs.iter().map(Into::into).collect(),
            input_rules: source.input_rules.as_ref().map(Into::into),
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
            .map(TryFrom::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let proofs = source
            .proofs
            .iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<_>, _>>()?;
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
        Self {
            required_outputs: source.required_outputs.iter().map(Into::into).collect(),
            max_tombstone_block: source.max_tombstone_block,
            partial_fill_outputs: source.partial_fill_outputs.iter().map(Into::into).collect(),
            partial_fill_change: source.partial_fill_change.as_ref().map(Into::into),
            min_partial_fill_value: source.min_partial_fill_value,
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
        let max_tombstone_block = source.max_tombstone_block;
        let partial_fill_outputs = source
            .partial_fill_outputs
            .iter()
            .map(RevealedTxOut::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let partial_fill_change = source
            .partial_fill_change
            .as_ref()
            .map(RevealedTxOut::try_from)
            .transpose()?;
        let min_partial_fill_value = source.min_partial_fill_value;
        Ok(InputRules {
            required_outputs,
            max_tombstone_block,
            partial_fill_outputs,
            partial_fill_change,
            min_partial_fill_value,
        })
    }
}

/// Convert RevealedTxOut --> external::RevealedTxOut.
impl From<&RevealedTxOut> for external::RevealedTxOut {
    fn from(source: &RevealedTxOut) -> Self {
        Self {
            tx_out: Some((&source.tx_out).into()),
            amount_shared_secret: source.amount_shared_secret.clone(),
        }
    }
}

/// Convert external::RevealedTxOut --> RevealedTxOut
impl TryFrom<&external::RevealedTxOut> for RevealedTxOut {
    type Error = ConversionError;

    fn try_from(source: &external::RevealedTxOut) -> Result<Self, Self::Error> {
        let tx_out =
            tx::TxOut::try_from(source.tx_out.as_ref().ok_or(Self::Error::ObjectMissing)?)?;
        let amount_shared_secret = source.amount_shared_secret.clone();
        if amount_shared_secret.len() != 32 {
            return Err(ConversionError::ArrayCastError);
        }
        Ok(RevealedTxOut {
            tx_out,
            amount_shared_secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::PublicAddress;
    use mc_crypto_keys::RistrettoPrivate;
    use mc_transaction_core::{
        onetime_keys::create_shared_secret, tokens::Mob, Amount, BlockVersion, MaskedAmount, Token,
    };
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    // tx::RevealedTxOut -> external::RevealedTxOut --> tx::RevealedTxOut
    fn test_revealed_tx_out_from_revealed_tx_out_stored() {
        let block_version = BlockVersion::THREE;
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let amount = Amount {
            value: 1u64 << 13,
            token_id: Mob::ID,
        };

        let recipient = PublicAddress::from_random(&mut rng);
        let tx_private_key = RistrettoPrivate::from_random(&mut rng);
        let tx_out = tx::TxOut::new(
            BlockVersion::THREE,
            amount,
            &recipient,
            &tx_private_key,
            Default::default(),
        )
        .unwrap();

        let shared_secret = create_shared_secret(recipient.view_public_key(), &tx_private_key);

        let amount_shared_secret =
            MaskedAmount::compute_amount_shared_secret(block_version, &shared_secret).unwrap();

        let rtxo = RevealedTxOut {
            tx_out,
            amount_shared_secret: amount_shared_secret.to_vec(),
        };

        let converted = external::RevealedTxOut::from(&rtxo);

        let recovered = RevealedTxOut::try_from(&converted).unwrap();
        assert_eq!(rtxo, recovered);
    }
}
