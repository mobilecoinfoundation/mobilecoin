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
