// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external:MintConfig/SetMintConfigTxPrefix/SetMintConfigTx.

use crate::{convert::ConversionError, external};
use mc_crypto_multisig::{MultiSig, SignerSet};
use mc_transaction_core::mint::{MintConfig, SetMintConfigTx, SetMintConfigTxPrefix};
use protobuf::RepeatedField;

use std::convert::TryFrom;

/// Convert MintConfig --> external::MintConfig.
impl From<&MintConfig> for external::MintConfig {
    fn from(src: &MintConfig) -> Self {
        let mut dst = external::MintConfig::new();
        dst.set_token_id(src.token_id);
        dst.set_signer_set((&src.signer_set).into());
        dst.set_mint_limit(src.mint_limit);
        dst
    }
}

/// Convert external::MintConfig --> MintConfig.
impl TryFrom<&external::MintConfig> for MintConfig {
    type Error = ConversionError;

    fn try_from(source: &external::MintConfig) -> Result<Self, Self::Error> {
        let signer_set = SignerSet::try_from(source.get_signer_set())?;
        Ok(Self {
            token_id: source.get_token_id(),
            signer_set,
            mint_limit: source.get_mint_limit(),
        })
    }
}

/// Convert SetMintConfigTxPrefix --> external::SetMintConfigTxPrefix.
impl From<&SetMintConfigTxPrefix> for external::SetMintConfigTxPrefix {
    fn from(src: &SetMintConfigTxPrefix) -> Self {
        let mut dst = external::SetMintConfigTxPrefix::new();
        dst.set_token_id(src.token_id);
        dst.set_configs(RepeatedField::from_vec(
            src.configs.iter().map(external::MintConfig::from).collect(),
        ));
        dst.set_nonce(src.nonce.clone());
        dst.set_tombstone_block(src.tombstone_block);
        dst
    }
}

/// Convert external::SetMintConfigTxPrefix --> SetMintConfigTxPrefix.
impl TryFrom<&external::SetMintConfigTxPrefix> for SetMintConfigTxPrefix {
    type Error = ConversionError;

    fn try_from(source: &external::SetMintConfigTxPrefix) -> Result<Self, Self::Error> {
        let configs: Vec<MintConfig> = source
            .get_configs()
            .iter()
            .map(|c| MintConfig::try_from(c))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            token_id: source.get_token_id(),
            configs,
            nonce: source.get_nonce().to_vec(),
            tombstone_block: source.get_tombstone_block(),
        })
    }
}

/// Convert SetMintConfigTx --> external::SetMintConfigTx.
impl From<&SetMintConfigTx> for external::SetMintConfigTx {
    fn from(src: &SetMintConfigTx) -> Self {
        let mut dst = external::SetMintConfigTx::new();
        dst.set_prefix((&src.prefix).into());
        dst.set_signature((&src.signature).into());
        dst
    }
}

/// Convert external::SetMintConfigTx --> SetMintConfigTx.
impl TryFrom<&external::SetMintConfigTx> for SetMintConfigTx {
    type Error = ConversionError;

    fn try_from(source: &external::SetMintConfigTx) -> Result<Self, Self::Error> {
        let prefix = SetMintConfigTxPrefix::try_from(source.get_prefix())?;
        let signature = MultiSig::try_from(source.get_signature())?;

        Ok(Self { prefix, signature })
    }
}
