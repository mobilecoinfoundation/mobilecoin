// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_transaction_core::ring_signature::ReducedTxOut

use crate::{external, ConversionError};
use mc_transaction_core::ring_signature::ReducedTxOut;

impl From<&ReducedTxOut> for external::ReducedTxOut {
    fn from(source: &ReducedTxOut) -> Self {
        let mut reduced_tx_out = external::ReducedTxOut::new();
        reduced_tx_out.set_public_key((&source.public_key).into());
        reduced_tx_out.set_target_key((&source.target_key).into());
        reduced_tx_out.set_commitment((&source.commitment).into());
        reduced_tx_out
    }
}

impl TryFrom<&external::ReducedTxOut> for ReducedTxOut {
    type Error = ConversionError;

    fn try_from(source: &external::ReducedTxOut) -> Result<Self, Self::Error> {
        Ok(ReducedTxOut {
            public_key: source.get_public_key().try_into()?,
            target_key: source.get_target_key().try_into()?,
            commitment: source.get_commitment().try_into()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::ristretto::CompressedRistretto;
    use mc_crypto_keys::CompressedRistrettoPublic;
    use mc_transaction_core::{ring_signature::ReducedTxOut, CompressedCommitment};
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::external;

    // Test converting between external::ReducedTxOut and
    // mc_transaction_core::ring_signature::ReducedTxOut
    #[test]
    fn test_reduced_tx_out_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        let public_key = CompressedRistrettoPublic::from_random(&mut rng);
        let target_key = CompressedRistrettoPublic::from_random(&mut rng);
        let commitment = CompressedCommitment::from(&CompressedRistretto::default());

        let reduced_tx_out = ReducedTxOut {
            public_key,
            target_key,
            commitment,
        };

        let reduced_tx_out_external: external::ReducedTxOut = (&reduced_tx_out).into();
        let recovered_reduced_tx_out: ReducedTxOut = (&reduced_tx_out_external).try_into().unwrap();

        assert_eq!(reduced_tx_out, recovered_reduced_tx_out);
    }
}
