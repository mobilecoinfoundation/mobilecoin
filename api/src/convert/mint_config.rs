// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external:MintConfig/MintConfigTxPrefix/MintConfigTx.

use crate::{external, ConversionError};
use mc_transaction_core::mint::{MintConfig, MintConfigTx, MintConfigTxPrefix};

/// Convert MintConfig --> external::MintConfig.
impl From<&MintConfig> for external::MintConfig {
    fn from(src: &MintConfig) -> Self {
        Self {
            token_id: src.token_id,
            signer_set: Some((&src.signer_set).into()),
            mint_limit: src.mint_limit,
        }
    }
}

/// Convert external::MintConfig --> MintConfig.
impl TryFrom<&external::MintConfig> for MintConfig {
    type Error = ConversionError;

    fn try_from(source: &external::MintConfig) -> Result<Self, Self::Error> {
        let signer_set = source
            .signer_set
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        Ok(Self {
            token_id: source.token_id,
            signer_set,
            mint_limit: source.mint_limit,
        })
    }
}

/// Convert MintConfigTxPrefix --> external::MintConfigTxPrefix.
impl From<&MintConfigTxPrefix> for external::MintConfigTxPrefix {
    fn from(src: &MintConfigTxPrefix) -> Self {
        Self {
            token_id: src.token_id,
            configs: src.configs.iter().map(external::MintConfig::from).collect(),
            nonce: src.nonce.clone(),
            tombstone_block: src.tombstone_block,
            total_mint_limit: src.total_mint_limit,
        }
    }
}

/// Convert external::MintConfigTxPrefix --> MintConfigTxPrefix.
impl TryFrom<&external::MintConfigTxPrefix> for MintConfigTxPrefix {
    type Error = ConversionError;

    fn try_from(source: &external::MintConfigTxPrefix) -> Result<Self, Self::Error> {
        let configs: Vec<MintConfig> = source
            .configs
            .iter()
            .map(MintConfig::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            token_id: source.token_id,
            configs,
            nonce: source.nonce.clone(),
            tombstone_block: source.tombstone_block,
            total_mint_limit: source.total_mint_limit,
        })
    }
}

/// Convert MintConfigTx --> external::MintConfigTx.
impl From<&MintConfigTx> for external::MintConfigTx {
    fn from(src: &MintConfigTx) -> Self {
        Self {
            prefix: Some((&src.prefix).into()),
            signature: Some((&src.signature).into()),
        }
    }
}

/// Convert external::MintConfigTx --> MintConfigTx.
impl TryFrom<&external::MintConfigTx> for MintConfigTx {
    type Error = ConversionError;

    fn try_from(source: &external::MintConfigTx) -> Result<Self, Self::Error> {
        let prefix = source
            .prefix
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        let signature = source
            .signature
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;

        Ok(Self { prefix, signature })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::ed25519_multisig::tests::{test_multi_sig, test_signer_set};
    use mc_util_serial::{decode, encode};
    use prost::Message;

    #[test]
    // MintConfig -> external::MintConfig -> MintConfig should be the identity
    // function.
    fn test_convert_mint_config() {
        let source = MintConfig {
            token_id: 123,
            signer_set: test_signer_set(),
            mint_limit: 10000,
        };

        // decode(encode(source)) should be the identity function.
        {
            let bytes = encode(&source);
            let recovered = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }

        // Converting mc_transaction_core::mint::MintConfig -> external::MintConfig ->
        // mc_transaction_core::mint::MintConfig should be the identity function.
        {
            let external = external::MintConfig::from(&source);
            let recovered = MintConfig::try_from(&external).unwrap();
            assert_eq!(source, recovered);
        }

        // Encoding with prost, decoding with protobuf should be the identity
        // function.
        {
            let bytes = encode(&source);
            let recovered = external::MintConfig::decode(bytes.as_slice()).unwrap();
            assert_eq!(recovered, external::MintConfig::from(&source));
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external = external::MintConfig::from(&source);
            let bytes = external.encode_to_vec();
            let recovered: MintConfig = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }
    }

    #[test]
    // MintConfigTx -> external::MintConfigTx -> MintConfigTx should be the
    // identity function.
    fn test_convert_mint_config_tx() {
        let source = MintConfigTx {
            prefix: MintConfigTxPrefix {
                token_id: 123,
                configs: vec![
                    MintConfig {
                        token_id: 123,
                        signer_set: test_signer_set(),
                        mint_limit: 10000,
                    },
                    MintConfig {
                        token_id: 456,
                        signer_set: test_signer_set(),
                        mint_limit: 20000,
                    },
                ],
                nonce: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                tombstone_block: 100,
                total_mint_limit: 123456,
            },
            signature: test_multi_sig(),
        };

        // decode(encode(source)) should be the identity function.
        {
            let bytes = encode(&source);
            let recovered = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }

        // Converting mc_transaction_core::mint::MintConfigTx ->
        // external::MintConfigTx -> mc_transaction_core::mint::
        // MintConfigTx should be the identity function.
        {
            let external = external::MintConfigTx::from(&source);
            let recovered = MintConfigTx::try_from(&external).unwrap();
            assert_eq!(source, recovered);
        }

        // Encoding with prost, decoding with protobuf should be the identity
        // function.
        {
            let bytes = encode(&source);
            let recovered = external::MintConfigTx::decode(bytes.as_slice()).unwrap();
            assert_eq!(recovered, external::MintConfigTx::from(&source));
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external = external::MintConfigTx::from(&source);
            let bytes = external.encode_to_vec();
            let recovered: MintConfigTx = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }
    }
}
