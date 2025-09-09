// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_transaction_core::ring_signature::ReducedTxOut

use crate::{external, ConversionError};
use mc_transaction_core::ring_signature::ReducedTxOut;

impl From<&ReducedTxOut> for external::ReducedTxOut {
    fn from(source: &ReducedTxOut) -> Self {
        Self {
            public_key: Some((&source.public_key).into()),
            target_key: Some((&source.target_key).into()),
            commitment: Some((&source.commitment).into()),
        }
    }
}

impl TryFrom<&external::ReducedTxOut> for ReducedTxOut {
    type Error = ConversionError;

    fn try_from(source: &external::ReducedTxOut) -> Result<Self, Self::Error> {
        let public_key = source
            .public_key
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        let target_key = source
            .target_key
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        let commitment = source
            .commitment
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        Ok(ReducedTxOut {
            public_key,
            target_key,
            commitment,
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
