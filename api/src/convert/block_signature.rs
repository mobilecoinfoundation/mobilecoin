//! Convert to/from blockchain::BlockSignature

use crate::{blockchain, convert::ConversionError, external};
use mc_crypto_keys::{Ed25519Public, Ed25519Signature};
use mc_transaction_core::BlockSignature;
use std::convert::TryFrom;

/// Convert BlockSignature --> blockchain::BlockSignature.
impl From<&BlockSignature> for blockchain::BlockSignature {
    fn from(src: &BlockSignature) -> Self {
        let mut dst = blockchain::BlockSignature::new();
        dst.set_signature(external::Ed25519Signature::from(src.signature()));
        dst.set_signer(external::Ed25519Public::from(src.signer()));
        dst.set_signed_at(src.signed_at());
        dst
    }
}

/// Convert blockchain::BlockSignature --> BlockSignature.
impl TryFrom<&blockchain::BlockSignature> for BlockSignature {
    type Error = ConversionError;

    fn try_from(source: &blockchain::BlockSignature) -> Result<Self, Self::Error> {
        let signature = Ed25519Signature::try_from(source.get_signature())?;
        let signer = Ed25519Public::try_from(source.get_signer())?;
        let signed_at = source.get_signed_at();
        Ok(BlockSignature::new(signature, signer, signed_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_crypto_keys::{Ed25519Private, Ed25519Signature};
    use mc_util_from_random::FromRandom;
    use mc_util_repr_bytes::ReprBytes;
    use protobuf::Message;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    // mc_transaction_core::BlockSignature --> blockchain::BlockSignature
    fn test_block_signature_from() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let source_block_signature = mc_transaction_core::BlockSignature::new(
            Ed25519Signature::new([1; 64]),
            (&Ed25519Private::from_random(&mut rng)).into(),
            31337,
        );

        let block_signature = blockchain::BlockSignature::from(&source_block_signature);
        assert_eq!(
            block_signature.get_signature().get_data(),
            source_block_signature.signature().as_ref()
        );
        assert_eq!(
            block_signature.get_signer().get_data(),
            source_block_signature.signer().to_bytes().as_slice(),
        );
        assert_eq!(
            block_signature.get_signed_at(),
            source_block_signature.signed_at(),
        );
    }

    #[test]
    // blockchain::BlockSignature -> mc_transaction_core::BlockSignature
    fn test_block_signature_try_from() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let expected_block_signature = mc_transaction_core::BlockSignature::new(
            Ed25519Signature::new([1; 64]),
            (&Ed25519Private::from_random(&mut rng)).into(),
            31337,
        );

        let mut source_block_signature = blockchain::BlockSignature::new();

        let mut signature = external::Ed25519Signature::new();
        signature.set_data(expected_block_signature.signature().to_bytes().to_vec());
        source_block_signature.set_signature(signature);

        let mut signer = external::Ed25519Public::new();
        signer.set_data(expected_block_signature.signer().to_bytes().to_vec());
        source_block_signature.set_signer(signer);

        source_block_signature.set_signed_at(31337);

        let block_signature =
            mc_transaction_core::BlockSignature::try_from(&source_block_signature).unwrap();
        assert_eq!(block_signature, expected_block_signature);
    }

    #[test]
    // the blockchain::BlockSignature definition matches the BlockSignature prost
    // attributes. This ensures the definition in the .proto files matches the
    // prost attributes inside the BlockSignature struct.
    fn test_blockchain_block_signature_matches_prost() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let source_block_signature = mc_transaction_core::BlockSignature::new(
            Ed25519Signature::new([1; 64]),
            (&Ed25519Private::from_random(&mut rng)).into(),
            31337,
        );

        // Encode using `protobuf`, decode using `prost`.
        {
            let blockchain_block_signature =
                blockchain::BlockSignature::from(&source_block_signature);
            let blockchain_block_signature_bytes =
                blockchain_block_signature.write_to_bytes().unwrap();

            let block_signature_from_prost: mc_transaction_core::BlockSignature =
                mc_util_serial::decode(&blockchain_block_signature_bytes).expect("failed decoding");
            assert_eq!(source_block_signature, block_signature_from_prost);
        }

        // Encode using `prost`, decode using `protobuf`.
        {
            let prost_block_signature_bytes = mc_util_serial::encode(&source_block_signature);
            let blockchain_block_signature =
                blockchain::BlockSignature::parse_from_bytes(&prost_block_signature_bytes)
                    .expect("failed decoding");

            assert_eq!(
                blockchain_block_signature,
                blockchain::BlockSignature::from(&source_block_signature)
            );
        }
    }
}
