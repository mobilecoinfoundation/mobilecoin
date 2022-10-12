// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_transaction_core::mint::VersionedSignerSet

use crate::{external, ConversionError};
use mc_transaction_core::mint::VersionedSignerSet;

impl From<&VersionedSignerSet> for external::MintConfig_oneof_signer_set {
    fn from(src: &VersionedSignerSet) -> Self {
        match src {
            VersionedSignerSet::V1(signer_set) => Self::signer_set_v1(signer_set.into()),

            VersionedSignerSet::V2(signer_set) => Self::signer_set_v2(signer_set.into()),
        }
    }
}

impl TryFrom<&external::MintConfig_oneof_signer_set> for VersionedSignerSet {
    type Error = ConversionError;

    fn try_from(src: &external::MintConfig_oneof_signer_set) -> Result<Self, Self::Error> {
        match src {
            external::MintConfig_oneof_signer_set::signer_set_v1(signer_set) => {
                Ok(VersionedSignerSet::V1(signer_set.try_into()?))
            }

            external::MintConfig_oneof_signer_set::signer_set_v2(signer_set) => {
                Ok(VersionedSignerSet::V2(signer_set.try_into()?))
            }
        }
    }
}

impl From<&VersionedSignerSet> for external::ValidatedMintConfigTx_oneof_signer_set {
    fn from(src: &VersionedSignerSet) -> Self {
        match src {
            VersionedSignerSet::V1(signer_set) => Self::signer_set_v1(signer_set.into()),

            VersionedSignerSet::V2(signer_set) => Self::signer_set_v2(signer_set.into()),
        }
    }
}

impl TryFrom<&external::ValidatedMintConfigTx_oneof_signer_set> for VersionedSignerSet {
    type Error = ConversionError;

    fn try_from(
        src: &external::ValidatedMintConfigTx_oneof_signer_set,
    ) -> Result<Self, Self::Error> {
        match src {
            external::ValidatedMintConfigTx_oneof_signer_set::signer_set_v1(signer_set) => {
                Ok(VersionedSignerSet::V1(signer_set.try_into()?))
            }

            external::ValidatedMintConfigTx_oneof_signer_set::signer_set_v2(signer_set) => {
                Ok(VersionedSignerSet::V2(signer_set.try_into()?))
            }
        }
    }
}
