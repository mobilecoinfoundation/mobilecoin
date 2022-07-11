// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::Ed25519SignerSet/Ed25519MultiSig.

use crate::{external, ConversionError};
use mc_crypto_keys::{Ed25519Public, Ed25519Signature};
use mc_crypto_multisig::{MultiSig, SignerSet};

/// Convert MultiSig<Ed25519Signature> --> external::Ed25519MultiSig.
impl From<&MultiSig<Ed25519Signature>> for external::Ed25519MultiSig {
    fn from(src: &MultiSig<Ed25519Signature>) -> Self {
        let mut dst = external::Ed25519MultiSig::new();
        dst.set_signatures(
            src.signatures()
                .iter()
                .map(external::Ed25519Signature::from)
                .collect(),
        );
        dst
    }
}

/// Convert external::Ed25519MultiSig --> MultiSig<Ed25519Signature>.
impl TryFrom<&external::Ed25519MultiSig> for MultiSig<Ed25519Signature> {
    type Error = ConversionError;

    fn try_from(source: &external::Ed25519MultiSig) -> Result<Self, Self::Error> {
        let signatures: Vec<Ed25519Signature> = source
            .get_signatures()
            .iter()
            .map(Ed25519Signature::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self::new(signatures))
    }
}

/// Convert SignerSet<Ed25519Public> --> external::Ed25519SignerSet.
impl From<&SignerSet<Ed25519Public>> for external::Ed25519SignerSet {
    fn from(src: &SignerSet<Ed25519Public>) -> Self {
        let mut dst = external::Ed25519SignerSet::new();
        dst.set_signers(
            src.signers()
                .iter()
                .map(external::Ed25519Public::from)
                .collect(),
        );
        dst.set_threshold(src.threshold());
        dst
    }
}

/// Convert external::Ed25519SignerSet --> SignerSet<Ed25519Public>.
impl TryFrom<&external::Ed25519SignerSet> for SignerSet<Ed25519Public> {
    type Error = ConversionError;

    fn try_from(source: &external::Ed25519SignerSet) -> Result<Self, Self::Error> {
        let signers: Vec<Ed25519Public> = source
            .get_signers()
            .iter()
            .map(Ed25519Public::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let threshold = source.get_threshold();

        Ok(Self::new(signers, threshold))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use mc_crypto_keys::{Ed25519Pair, Signer};
    use mc_util_from_random::FromRandom;
    use mc_util_serial::{decode, encode};
    use protobuf::Message;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    // Generate a signer set for testing purposes.
    pub fn test_signer_set() -> SignerSet<Ed25519Public> {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer1 = Ed25519Pair::from_random(&mut rng);
        let signer2 = Ed25519Pair::from_random(&mut rng);
        let signer3 = Ed25519Pair::from_random(&mut rng);

        SignerSet::new(
            vec![
                signer1.public_key(),
                signer2.public_key(),
                signer3.public_key(),
            ],
            2,
        )
    }

    // Generate a multi sig for testing purpses.
    pub fn test_multi_sig() -> MultiSig<Ed25519Signature> {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer1 = Ed25519Pair::from_random(&mut rng);
        let signer2 = Ed25519Pair::from_random(&mut rng);

        let message = b"this is a test";

        // Try with just one valid signature, we should fail to verify.
        MultiSig::new(vec![
            signer1.try_sign(message.as_ref()).unwrap(),
            signer2.try_sign(message.as_ref()).unwrap(),
        ])
    }

    #[test]
    // SignerSet<Ed25519Public> -> external::Ed25519SignerSet ->
    // SignerSet<Ed25519Public> should be the identity function.
    fn test_convert_ed25519_signer_set() {
        let source = test_signer_set();

        // decode(encode(source)) should be the identity function.
        {
            let bytes = encode(&source);
            let recovered = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }

        // SignerSet<Ed25519Public> -> external::Ed25519SignerSet ->
        // SignerSet<Ed25519Public> should be the identity function.
        {
            let external = external::Ed25519SignerSet::from(&source);
            let recovered = SignerSet::try_from(&external).unwrap();
            assert_eq!(source, recovered);
        }

        // Encoding with prost, decoding with protobuf should be the identity
        // function.
        {
            let bytes = encode(&source);
            let recovered = external::Ed25519SignerSet::parse_from_bytes(&bytes).unwrap();
            assert_eq!(recovered, external::Ed25519SignerSet::from(&source));
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external = external::Ed25519SignerSet::from(&source);
            let bytes = external.write_to_bytes().unwrap();
            let recovered: SignerSet<Ed25519Public> = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }
    }

    #[test]
    // MultiSig<Ed25519Public> -> external::Ed25519MultiSig ->
    // MultiSig<Ed25519Public> should be the identity function.
    fn test_convert_ed25519_multi_sig() {
        let source = test_multi_sig();

        // decode(encode(source)) should be the identity function.
        {
            let bytes = encode(&source);
            let recovered = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }

        // Converting MultiSig<Ed25519Public> -> external::Ed25519MultiSig ->
        // MultiSig<Ed25519Public> should be the identity function.
        {
            let external = external::Ed25519MultiSig::from(&source);
            let recovered = MultiSig::try_from(&external).unwrap();
            assert_eq!(source, recovered);
        }

        // Encoding with prost, decoding with protobuf should be the identity
        // function.
        {
            let bytes = encode(&source);
            let recovered = external::Ed25519MultiSig::parse_from_bytes(&bytes).unwrap();
            assert_eq!(recovered, external::Ed25519MultiSig::from(&source));
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external = external::Ed25519MultiSig::from(&source);
            let bytes = external.write_to_bytes().unwrap();
            let recovered: MultiSig<Ed25519Signature> = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }
    }
}
