// Copyright (c) 2018-2022 The MobileCoin Foundation

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
            .unwrap_or(&Default::default())
            .try_into()?;
        let signer = source
            .signer
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        let signed_at = source.signed_at;
        Ok(BlockSignature::new(signature, signer, signed_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external;
    use mc_crypto_keys::{Ed25519Private, Ed25519Signature};
    use mc_util_from_random::FromRandom;
    use mc_util_repr_bytes::ReprBytes;
    use prost::Message;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    // BlockSignature --> blockchain::BlockSignature
    fn test_block_signature_from() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let source_block_signature = BlockSignature::new(
            Ed25519Signature::new([1; 64]),
            (&Ed25519Private::from_random(&mut rng)).into(),
            31337,
        );

        let block_signature = blockchain::BlockSignature::from(&source_block_signature);
        assert_eq!(
            block_signature.signature.unwrap().data,
            source_block_signature.signature().as_ref()
        );
        assert_eq!(
            block_signature.signer.unwrap().data,
            source_block_signature.signer().to_bytes().as_slice(),
        );
        assert_eq!(
            block_signature.signed_at,
            source_block_signature.signed_at(),
        );
    }

    #[test]
    // blockchain::BlockSignature -> BlockSignature
    fn test_block_signature_try_from() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let expected_block_signature = BlockSignature::new(
            Ed25519Signature::new([1; 64]),
            (&Ed25519Private::from_random(&mut rng)).into(),
            31337,
        );

        let source_block_signature = blockchain::BlockSignature {
            signature: Some(external::Ed25519Signature {
                data: expected_block_signature.signature().to_bytes().to_vec(),
            }),
            signer: Some(external::Ed25519Public {
                data: expected_block_signature.signer().to_bytes().to_vec(),
            }),
            signed_at: 31337,
        };

        let block_signature = BlockSignature::try_from(&source_block_signature).unwrap();
        assert_eq!(block_signature, expected_block_signature);
    }

    #[test]
    // the blockchain::BlockSignature definition matches the BlockSignature prost
    // attributes. This ensures the definition in the .proto files matches the
    // prost attributes inside the BlockSignature struct.
    fn test_blockchain_block_signature_matches_prost() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let source_block_signature = BlockSignature::new(
            Ed25519Signature::new([1; 64]),
            (&Ed25519Private::from_random(&mut rng)).into(),
            31337,
        );

        // Encode using `protobuf`, decode using `prost`.
        {
            let blockchain_block_signature =
                blockchain::BlockSignature::from(&source_block_signature);
            let blockchain_block_signature_bytes = blockchain_block_signature.encode_to_vec();

            let block_signature_from_prost: BlockSignature =
                mc_util_serial::decode(&blockchain_block_signature_bytes).expect("failed decoding");
            assert_eq!(source_block_signature, block_signature_from_prost);
        }

        // Encode using `prost`, decode using `protobuf`.
        {
            let prost_block_signature_bytes = mc_util_serial::encode(&source_block_signature);
            let blockchain_block_signature =
                blockchain::BlockSignature::decode(prost_block_signature_bytes.as_slice())
                    .expect("failed decoding");

            assert_eq!(
                blockchain_block_signature,
                blockchain::BlockSignature::from(&source_block_signature)
            );
        }
    }
}
