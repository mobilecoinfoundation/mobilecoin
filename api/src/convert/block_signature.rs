//! Convert to/from blockchain::BlockSignature

use crate::{blockchain, ConversionError};
use mc_blockchain_types::BlockSignature;

/// Convert BlockSignature --> blockchain::BlockSignature.
impl From<&BlockSignature> for blockchain::BlockSignature {
    fn from(src: &BlockSignature) -> Self {
        Self {
            signature: Some(src.signature().into()),
            signer: Some(src.signer().into()),
            signed_at: src.signed_at(),
        }
    }
}

/// Convert blockchain::BlockSignature --> BlockSignature.
impl TryFrom<&blockchain::BlockSignature> for BlockSignature {
    type Error = ConversionError;

    fn try_from(source: &blockchain::BlockSignature) -> Result<Self, Self::Error> {
        let signature = source
            .signature
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;
        let signer = source
            .signer
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        Ok(BlockSignature::new(signature, signer, source.signed_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_crypto_keys::{Ed25519Private, Ed25519Signature};
    use mc_util_from_random::FromRandom;
    use mc_util_serial::round_trip_message;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_block_signature_round_trip() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let source_block_signature = BlockSignature::new(
            Ed25519Signature::new([1; 64]),
            (&Ed25519Private::from_random(&mut rng)).into(),
            31337,
        );

        round_trip_message::<BlockSignature, blockchain::BlockSignature>(&source_block_signature);
    }
}
