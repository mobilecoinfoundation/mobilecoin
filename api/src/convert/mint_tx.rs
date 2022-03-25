// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external:MintTx/MintTxPrefix.

use crate::{convert::ConversionError, external};
use mc_crypto_keys::RistrettoPublic;
use mc_crypto_multisig::MultiSig;
use mc_transaction_core::mint::{MintTx, MintTxPrefix};

use std::convert::TryFrom;

/// Convert MintTxPrefix --> external::MintTxPrefix.
impl From<&MintTxPrefix> for external::MintTxPrefix {
    fn from(src: &MintTxPrefix) -> Self {
        let mut dst = external::MintTxPrefix::new();
        dst.set_token_id(src.token_id);
        dst.set_amount(src.amount);
        dst.set_view_public_key((&src.view_public_key).into());
        dst.set_spend_public_key((&src.spend_public_key).into());
        dst.set_nonce(src.nonce.clone());
        dst.set_tombstone_block(src.tombstone_block);
        dst
    }
}

/// Convert external::MintTxPrefix --> MintTxPrefix.
impl TryFrom<&external::MintTxPrefix> for MintTxPrefix {
    type Error = ConversionError;

    fn try_from(source: &external::MintTxPrefix) -> Result<Self, Self::Error> {
        let view_public_key = RistrettoPublic::try_from(source.get_view_public_key())?;
        let spend_public_key = RistrettoPublic::try_from(source.get_spend_public_key())?;

        Ok(Self {
            token_id: source.get_token_id(),
            amount: source.get_amount(),
            view_public_key,
            spend_public_key,
            nonce: source.get_nonce().to_vec(),
            tombstone_block: source.get_tombstone_block(),
        })
    }
}

/// Convert MintTx --> external::MintTx.
impl From<&MintTx> for external::MintTx {
    fn from(src: &MintTx) -> Self {
        let mut dst = external::MintTx::new();
        dst.set_prefix((&src.prefix).into());
        dst.set_signature((&src.signature).into());
        dst
    }
}

/// Convert external::MintTx --> MintTx.
impl TryFrom<&external::MintTx> for MintTx {
    type Error = ConversionError;

    fn try_from(source: &external::MintTx) -> Result<Self, Self::Error> {
        let prefix = MintTxPrefix::try_from(source.get_prefix())?;
        let signature = MultiSig::try_from(source.get_signature())?;

        Ok(Self { prefix, signature })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::ed25519_multisig::tests::test_multi_sig;
    use mc_util_from_random::FromRandom;
    use mc_util_serial::{decode, encode};
    use protobuf::Message;
    use rand_core::{RngCore, SeedableRng};
    use rand_hc::Hc128Rng;

    #[test]
    // MintTx -> external::MintTx -> MintTx should be the identity
    // function.
    fn test_convert_mint_tx() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);

        let source = MintTx {
            prefix: MintTxPrefix {
                token_id: rng.next_u32(),
                amount: rng.next_u64(),
                view_public_key: RistrettoPublic::from_random(&mut rng),
                spend_public_key: RistrettoPublic::from_random(&mut rng),
                nonce: vec![3u8; 32],
                tombstone_block: rng.next_u64(),
            },
            signature: test_multi_sig(),
        };

        // decode(encode(source)) should be the identity function.
        {
            let bytes = encode(&source);
            let recovered = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }

        // Converting mc_transaction_core::mint::MintTx -> external::MintTx ->
        // mc_transaction_core::mint::MintTx should be the identity function.
        {
            let external = external::MintTx::from(&source);
            let recovered = MintTx::try_from(&external).unwrap();
            assert_eq!(source, recovered);
        }

        // Encoding with prost, decoding with protobuf should be the identity
        // function.
        {
            let bytes = encode(&source);
            let recovered = external::MintTx::parse_from_bytes(&bytes).unwrap();
            assert_eq!(recovered, external::MintTx::from(&source));
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external = external::MintTx::from(&source);
            let bytes = external.write_to_bytes().unwrap();
            let recovered: MintTx = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }
    }
}
