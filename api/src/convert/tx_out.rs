//! Convert to/from external::TxOut

use crate::{external, ConversionError};
use mc_transaction_core::{tx::TxOut, EncryptedMemo};

/// Convert TxOut --> external::TxOut.
impl From<&TxOut> for external::TxOut {
    fn from(source: &TxOut) -> Self {
        Self {
            masked_amount: Some((&source.masked_amount).into()),
            target_key: Some((&source.target_key).into()),
            public_key: Some((&source.public_key).into()),
            e_fog_hint: Some((&source.e_fog_hint).into()),
            e_memo: source.e_memo.as_ref().map(external::EncryptedMemo::from),
        }
    }
}

/// Convert external::TxOut --> TxOut.
impl TryFrom<&external::TxOut> for TxOut {
    type Error = ConversionError;

    fn try_from(source: &external::TxOut) -> Result<Self, Self::Error> {
        let masked_amount = source
            .masked_amount
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        let target_key = source
            .target_key
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        let public_key = source
            .public_key
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        let e_fog_hint = source
            .e_fog_hint
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        let e_memo = source
            .e_memo
            .as_ref()
            .map(EncryptedMemo::try_from)
            .transpose()?;

        Ok(Self {
            masked_amount,
            target_key,
            public_key,
            e_fog_hint,
            e_memo,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic_array::GenericArray;
    use mc_crypto_keys::RistrettoPublic;
    use mc_transaction_core::{
        encrypted_fog_hint::ENCRYPTED_FOG_HINT_LEN, tokens::Mob, Amount, MaskedAmount, Token,
    };
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    // TxOut -> external::TxOut --> TxOut
    fn test_tx_out_from_tx_out_stored() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let amount = Amount {
            value: 1u64 << 13,
            token_id: Mob::ID,
        };
        let source = TxOut {
            masked_amount: MaskedAmount::new(amount, &RistrettoPublic::from_random(&mut rng))
                .unwrap(),
            target_key: RistrettoPublic::from_random(&mut rng).into(),
            public_key: RistrettoPublic::from_random(&mut rng).into(),
            e_fog_hint: (&[0u8; ENCRYPTED_FOG_HINT_LEN]).into(),
            e_memo: None,
        };

        let converted = external::TxOut::from(&source);

        let recovered_tx_out = TxOut::try_from(&converted).unwrap();
        assert_eq!(source.masked_amount, recovered_tx_out.masked_amount);
    }

    #[test]
    // TxOut -> external::TxOut --> TxOut
    fn test_tx_out_from_tx_out_stored_with_memo() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let amount = Amount {
            value: 1u64 << 13,
            token_id: Mob::ID,
        };
        let source = TxOut {
            masked_amount: MaskedAmount::new(amount, &RistrettoPublic::from_random(&mut rng))
                .unwrap(),
            target_key: RistrettoPublic::from_random(&mut rng).into(),
            public_key: RistrettoPublic::from_random(&mut rng).into(),
            e_fog_hint: (&[0u8; ENCRYPTED_FOG_HINT_LEN]).into(),
            e_memo: Some((*GenericArray::from_slice(&[9u8; 66])).into()),
        };

        let converted = external::TxOut::from(&source);

        let recovered_tx_out = TxOut::try_from(&converted).unwrap();
        assert_eq!(source.masked_amount, recovered_tx_out.masked_amount);
        assert_eq!(source.target_key, recovered_tx_out.target_key);
        assert_eq!(source.public_key, recovered_tx_out.public_key);
        assert_eq!(source.e_fog_hint, recovered_tx_out.e_fog_hint);
        assert_eq!(source.e_memo, recovered_tx_out.e_memo);
    }
}
