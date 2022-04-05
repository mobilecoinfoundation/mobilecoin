// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external:MintConfig/MintConfigTxPrefix/MintConfigTx.

use crate::{convert::ConversionError, external};
use mc_crypto_multisig::{MultiSig, SignerSet};
use mc_transaction_core::mint::{MintConfig, MintConfigTx, MintConfigTxPrefix};

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

/// Convert MintConfigTxPrefix --> external::MintConfigTxPrefix.
impl From<&MintConfigTxPrefix> for external::MintConfigTxPrefix {
    fn from(src: &MintConfigTxPrefix) -> Self {
        let mut dst = external::MintConfigTxPrefix::new();
        dst.set_token_id(src.token_id);
        dst.set_configs(src.configs.iter().map(external::MintConfig::from).collect());
        dst.set_nonce(src.nonce.clone());
        dst.set_tombstone_block(src.tombstone_block);
        dst.set_total_mint_limit(src.total_mint_limit);
        dst
    }
}

/// Convert external::MintConfigTxPrefix --> MintConfigTxPrefix.
impl TryFrom<&external::MintConfigTxPrefix> for MintConfigTxPrefix {
    type Error = ConversionError;

    fn try_from(source: &external::MintConfigTxPrefix) -> Result<Self, Self::Error> {
        let configs: Vec<MintConfig> = source
            .get_configs()
            .iter()
            .map(MintConfig::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            token_id: source.get_token_id(),
            configs,
            nonce: source.get_nonce().to_vec(),
            tombstone_block: source.get_tombstone_block(),
            total_mint_limit: source.get_total_mint_limit(),
        })
    }
}

/// Convert MintConfigTx --> external::MintConfigTx.
impl From<&MintConfigTx> for external::MintConfigTx {
    fn from(src: &MintConfigTx) -> Self {
        let mut dst = external::MintConfigTx::new();
        dst.set_prefix((&src.prefix).into());
        dst.set_signature((&src.signature).into());
        dst
    }
}

/// Convert external::MintConfigTx --> MintConfigTx.
impl TryFrom<&external::MintConfigTx> for MintConfigTx {
    type Error = ConversionError;

    fn try_from(source: &external::MintConfigTx) -> Result<Self, Self::Error> {
        let prefix = MintConfigTxPrefix::try_from(source.get_prefix())?;
        let signature = MultiSig::try_from(source.get_signature())?;

        Ok(Self { prefix, signature })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::ed25519_multisig::tests::{test_multi_sig, test_signer_set};
    use mc_util_serial::{decode, encode};
    use protobuf::Message;

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
            let recovered = external::MintConfig::parse_from_bytes(&bytes).unwrap();
            assert_eq!(recovered, external::MintConfig::from(&source));
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external = external::MintConfig::from(&source);
            let bytes = external.write_to_bytes().unwrap();
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
            let recovered = external::MintConfigTx::parse_from_bytes(&bytes).unwrap();
            assert_eq!(recovered, external::MintConfigTx::from(&source));
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external = external::MintConfigTx::from(&source);
            let bytes = external.write_to_bytes().unwrap();
            let recovered: MintConfigTx = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }
    }
}
