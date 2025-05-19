// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::TxOut

use crate::{external, ConversionError};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_transaction_core::{encrypted_fog_hint::EncryptedFogHint, tx, EncryptedMemo, MaskedAmount};

/// Convert tx::TxOut --> external::TxOut.
impl From<&tx::TxOut> for external::TxOut {
    fn from(source: &tx::TxOut) -> Self {
        Self {
            target_key: Some((&source.target_key).into()),
            public_key: Some((&source.public_key).into()),
            e_fog_hint: Some(external::EncryptedFogHint {
                data: source.e_fog_hint.as_ref().to_vec(),
            }),
            e_memo: source.e_memo.as_ref().map(|m| external::EncryptedMemo {
                data: AsRef::<[u8]>::as_ref(m).to_vec(),
            }),
            masked_amount: source.masked_amount.as_ref().map(Into::into),
        }
    }
}

/// Convert external::TxOut --> tx::TxOut.
impl TryFrom<&external::TxOut> for tx::TxOut {
    type Error = ConversionError;

    fn try_from(source: &external::TxOut) -> Result<Self, Self::Error> {
        let oneof_masked_amount = source
            .masked_amount
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?;
        let masked_amount = Some(MaskedAmount::try_from(oneof_masked_amount)?);

        let target_key: CompressedRistrettoPublic = RistrettoPublic::try_from(
            source
                .target_key
                .as_ref()
                .unwrap_or(&Default::default())
                .data
                .as_slice(),
        )
        .map_err(|_| ConversionError::KeyCastError)?
        .into();

        let public_key: CompressedRistrettoPublic = RistrettoPublic::try_from(
            source
                .public_key
                .as_ref()
                .unwrap_or(&Default::default())
                .data
                .as_slice(),
        )
        .map_err(|_| ConversionError::KeyCastError)?
        .into();

        let e_fog_hint = EncryptedFogHint::try_from(
            source
                .e_fog_hint
                .as_ref()
                .unwrap_or(&Default::default())
                .data
                .as_slice(),
        )
        .map_err(|_| ConversionError::ArrayCastError)?;

        let e_memo = source
            .e_memo
            .as_ref()
            .map(|m| {
                EncryptedMemo::try_from(m.data.as_slice())
                    .map_err(|_| ConversionError::ArrayCastError)
            })
            .transpose()?;

        let tx_out = tx::TxOut {
            masked_amount,
            target_key,
            public_key,
            e_fog_hint,
            e_memo,
        };
        Ok(tx_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_crypto_keys::RistrettoPrivate;
    use mc_transaction_core::{tokens::Mob, Amount, BlockVersion, PublicAddress, Token};
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    // tx::TxOut -> external::TxOut --> tx::TxOut
    fn test_tx_out_from_tx_out_stored() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let amount = Amount {
            value: 1u64 << 13,
            token_id: Mob::ID,
        };
        let source = tx::TxOut::new(
            BlockVersion::ZERO,
            amount,
            &PublicAddress::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let converted = external::TxOut::from(&source);

        let recovered_tx_out = tx::TxOut::try_from(&converted).unwrap();
        assert_eq!(source.masked_amount, recovered_tx_out.masked_amount);
    }

    #[test]
    // tx::TxOut -> external::TxOut --> tx::TxOut
    fn test_tx_out_from_tx_out_stored_with_memo() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let amount = Amount {
            value: 1u64 << 13,
            token_id: Mob::ID,
        };
        let source = tx::TxOut::new(
            BlockVersion::MAX,
            amount,
            &PublicAddress::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let converted = external::TxOut::from(&source);

        let recovered_tx_out = tx::TxOut::try_from(&converted).unwrap();
        assert_eq!(source.masked_amount, recovered_tx_out.masked_amount);
        assert_eq!(source.target_key, recovered_tx_out.target_key);
        assert_eq!(source.public_key, recovered_tx_out.public_key);
        assert_eq!(source.e_fog_hint, recovered_tx_out.e_fog_hint);
        assert_eq!(source.e_memo, recovered_tx_out.e_memo);
    }
}
