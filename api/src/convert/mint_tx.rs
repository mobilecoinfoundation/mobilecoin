// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external:MintTx/MintTxPrefix.

use crate::{external, ConversionError};
use mc_transaction_core::mint::{MintTx, MintTxPrefix};

/// Convert MintTxPrefix --> external::MintTxPrefix.
impl From<&MintTxPrefix> for external::MintTxPrefix {
    fn from(src: &MintTxPrefix) -> Self {
        Self {
            amount: src.amount,
            token_id: src.token_id,
            nonce: src.nonce.clone(),
            tombstone_block: src.tombstone_block,
            view_public_key: Some((&src.view_public_key).into()),
            spend_public_key: Some((&src.spend_public_key).into()),
        }
    }
}

/// Convert external::MintTxPrefix --> MintTxPrefix.
impl TryFrom<&external::MintTxPrefix> for MintTxPrefix {
    type Error = ConversionError;

    fn try_from(source: &external::MintTxPrefix) -> Result<Self, Self::Error> {
        let view_public_key = source
            .view_public_key
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;
        let spend_public_key = source
            .spend_public_key
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        Ok(Self {
            token_id: source.token_id,
            amount: source.amount,
            view_public_key,
            spend_public_key,
            nonce: source.nonce.to_vec(),
            tombstone_block: source.tombstone_block,
        })
    }
}

/// Convert MintTx --> external::MintTx.
impl From<&MintTx> for external::MintTx {
    fn from(src: &MintTx) -> Self {
        Self {
            prefix: Some((&src.prefix).into()),
            signature: Some((&src.signature).into()),
        }
    }
}

/// Convert external::MintTx --> MintTx.
impl TryFrom<&external::MintTx> for MintTx {
    type Error = ConversionError;

    fn try_from(source: &external::MintTx) -> Result<Self, Self::Error> {
        let prefix = source
            .prefix
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;
        let signature = source
            .signature
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        Ok(Self { prefix, signature })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::ed25519_multisig::tests::test_multi_sig;
    use mc_crypto_keys::RistrettoPublic;
    use mc_util_from_random::FromRandom;
    use mc_util_serial::round_trip_message;
    use mc_util_test_helper::{get_seeded_rng, RngCore};

    #[test]
    fn test_convert_mint_tx() {
        let mut rng = get_seeded_rng();

        let source = MintTx {
            prefix: MintTxPrefix {
                token_id: rng.next_u64(),
                amount: rng.next_u64(),
                view_public_key: RistrettoPublic::from_random(&mut rng),
                spend_public_key: RistrettoPublic::from_random(&mut rng),
                nonce: vec![3u8; 32],
                tombstone_block: rng.next_u64(),
            },
            signature: test_multi_sig(),
        };

        round_trip_message::<MintTx, external::MintTx>(&source);
    }
}
