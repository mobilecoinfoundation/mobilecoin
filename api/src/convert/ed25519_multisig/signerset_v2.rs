// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::Ed25519SignerSetV2 (and associated oneof data
//! types)

use crate::{external, ConversionError};
use mc_crypto_keys::Ed25519Public;
use mc_crypto_multisig::{SignerContainer, SignerEntity, SignerSetV2};

// Convert from prost to protobuf

impl From<&SignerEntity<Ed25519Public>> for external::Ed25519SignerContainer_oneof_signer_entity {
    fn from(src: &SignerEntity<Ed25519Public>) -> Self {
        match src {
            SignerEntity::Single(single_signer) => Self::single(single_signer.into()),
            SignerEntity::Multi(signer_set) => Self::multi(signer_set.into()),
        }
    }
}

impl From<&SignerContainer<Ed25519Public>> for external::Ed25519SignerContainer {
    fn from(src: &SignerContainer<Ed25519Public>) -> Self {
        Self {
            signer_entity: src.entity.as_ref().map(Into::into),
            ..Default::default()
        }
    }
}

impl From<&SignerSetV2<Ed25519Public>> for external::Ed25519SignerSetV2 {
    fn from(src: &SignerSetV2<Ed25519Public>) -> Self {
        Self {
            signers: src.signers().iter().map(Into::into).collect(),
            threshold: src.threshold(),
            ..Default::default()
        }
    }
}

// Convert from protobuf to prose

impl TryFrom<&external::Ed25519SignerContainer_oneof_signer_entity>
    for SignerEntity<Ed25519Public>
{
    type Error = ConversionError;

    fn try_from(
        source: &external::Ed25519SignerContainer_oneof_signer_entity,
    ) -> Result<Self, Self::Error> {
        match source {
            external::Ed25519SignerContainer_oneof_signer_entity::single(single_signer) => {
                Ok(Self::Single(single_signer.try_into()?))
            }
            external::Ed25519SignerContainer_oneof_signer_entity::multi(signer_set) => {
                Ok(Self::Multi(signer_set.try_into()?))
            }
        }
    }
}

impl TryFrom<&external::Ed25519SignerContainer> for SignerContainer<Ed25519Public> {
    type Error = ConversionError;

    fn try_from(source: &external::Ed25519SignerContainer) -> Result<Self, Self::Error> {
        Ok(Self {
            entity: source
                .signer_entity
                .as_ref()
                .map(TryInto::try_into)
                .transpose()?,
        })
    }
}

impl TryFrom<&external::Ed25519SignerSetV2> for SignerSetV2<Ed25519Public> {
    type Error = ConversionError;

    fn try_from(source: &external::Ed25519SignerSetV2) -> Result<Self, Self::Error> {
        let signers: Vec<_> = source
            .get_signers()
            .iter()
            .map(TryFrom::try_from)
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
    pub fn test_signer_set_v2() -> SignerSetV2<Ed25519Public> {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer1 = Ed25519Pair::from_random(&mut rng);
        let signer2 = Ed25519Pair::from_random(&mut rng);
        let signer3 = Ed25519Pair::from_random(&mut rng);

        let signer4 = Ed25519Pair::from_random(&mut rng);
        let signer5 = Ed25519Pair::from_random(&mut rng);
        let signer6 = Ed25519Pair::from_random(&mut rng);

        let signer7 = Ed25519Pair::from_random(&mut rng);

        let set1 = SignerSetV2::new(
            vec![
                signer1.public_key().into(),
                signer2.public_key().into(),
                signer3.public_key().into(),
            ],
            2,
        );

        let set2 = SignerSetV2::new(
            vec![
                signer4.public_key().into(),
                signer5.public_key().into(),
                signer6.public_key().into(),
            ],
            3,
        );

        SignerSetV2::new(
            vec![set1.into(), set2.into(), signer7.public_key().into()],
            1,
        )
    }

    #[test]
    // SignerSetV2<Ed25519Public> -> external::Ed25519SignerSetV2 ->
    // SignerSetV2<Ed25519Public> should be the identity function.
    fn test_convert_ed25519_signer_set_v2() {
        let source = test_signer_set_v2();

        // decode(encode(source)) should be the identity function.
        {
            let bytes = encode(&source);
            let recovered = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }

        // SignerSet<Ed25519Public> -> external::Ed25519SignerSetV2 ->
        // SignerSet<Ed25519Public> should be the identity function.
        {
            let external = external::Ed25519SignerSetV2::from(&source);
            let recovered = SignerSetV2::try_from(&external).unwrap();
            assert_eq!(source, recovered);
        }

        // Encoding with prost, decoding with protobuf should be the identity
        // function.
        {
            let bytes = encode(&source);
            let recovered = external::Ed25519SignerSetV2::parse_from_bytes(&bytes).unwrap();
            assert_eq!(recovered, external::Ed25519SignerSetV2::from(&source));
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external = external::Ed25519SignerSetV2::from(&source);
            let bytes = external.write_to_bytes().unwrap();
            let recovered: SignerSetV2<Ed25519Public> = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }
    }
}
