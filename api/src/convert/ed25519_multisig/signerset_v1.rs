// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::Ed25519SignerSetV1

use crate::{external, ConversionError};
use mc_crypto_keys::Ed25519Public;
use mc_crypto_multisig::SignerSetV1;

impl From<&SignerSetV1<Ed25519Public>> for external::Ed25519SignerSetV1 {
    fn from(src: &SignerSetV1<Ed25519Public>) -> Self {
        let mut dst = external::Ed25519SignerSetV1::new();
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

impl TryFrom<&external::Ed25519SignerSetV1> for SignerSetV1<Ed25519Public> {
    type Error = ConversionError;

    fn try_from(source: &external::Ed25519SignerSetV1) -> Result<Self, Self::Error> {
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
    use mc_crypto_keys::Ed25519Pair;
    use mc_util_from_random::FromRandom;
    use mc_util_serial::{decode, encode};
    use protobuf::Message;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    // Generate a signer set for testing purposes.
    pub fn test_signer_set_v1() -> SignerSetV1<Ed25519Public> {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer1 = Ed25519Pair::from_random(&mut rng);
        let signer2 = Ed25519Pair::from_random(&mut rng);
        let signer3 = Ed25519Pair::from_random(&mut rng);

        SignerSetV1::new(
            vec![
                signer1.public_key(),
                signer2.public_key(),
                signer3.public_key(),
            ],
            2,
        )
    }
    #[test]
    // SignerSetV1<Ed25519Public> -> external::Ed25519SignerSetV1 ->
    // SignerSetV1<Ed25519Public> should be the identity function.
    fn test_convert_ed25519_signer_set_v1() {
        let source = test_signer_set_v1();

        // decode(encode(source)) should be the identity function.
        {
            let bytes = encode(&source);
            let recovered = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }

        // SignerSet<Ed25519Public> -> external::Ed25519SignerSetV1 ->
        // SignerSet<Ed25519Public> should be the identity function.
        {
            let external = external::Ed25519SignerSetV1::from(&source);
            let recovered = SignerSetV1::try_from(&external).unwrap();
            assert_eq!(source, recovered);
        }

        // Encoding with prost, decoding with protobuf should be the identity
        // function.
        {
            let bytes = encode(&source);
            let recovered = external::Ed25519SignerSetV1::parse_from_bytes(&bytes).unwrap();
            assert_eq!(recovered, external::Ed25519SignerSetV1::from(&source));
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external = external::Ed25519SignerSetV1::from(&source);
            let bytes = external.write_to_bytes().unwrap();
            let recovered: SignerSetV1<Ed25519Public> = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }
    }
}
