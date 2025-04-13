// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert between the Rust and Protobuf versions of [ValidatedMintConfigTx]

use crate::{external, ConversionError};
use mc_transaction_core::mint::ValidatedMintConfigTx;

/// Convert ValidatedMintConfigTx --> external::ValidatedMintConfigTx.
impl From<&ValidatedMintConfigTx> for external::ValidatedMintConfigTx {
    fn from(src: &ValidatedMintConfigTx) -> Self {
        Self {
            mint_config_tx: Some((&src.mint_config_tx).into()),
            signer_set: Some((&src.signer_set).into()),
        }
    }
}

/// Convert external::ValidatedMintConfigTx --> ValidatedMintConfigTx.
impl TryFrom<&external::ValidatedMintConfigTx> for ValidatedMintConfigTx {
    type Error = ConversionError;

    fn try_from(source: &external::ValidatedMintConfigTx) -> Result<Self, Self::Error> {
        let mint_config_tx = source
            .mint_config_tx
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        let signer_set = source
            .signer_set
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        Ok(Self {
            mint_config_tx,
            signer_set,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::ed25519_multisig::tests::{test_multi_sig, test_signer_set};
    use mc_transaction_core::mint::{MintConfig, MintConfigTx, MintConfigTxPrefix};
    use mc_util_serial::{decode, encode};
    use prost::Message;

    #[test]
    // ValidatedMintConfigTx -> external::ValidatedMintConfigTx ->
    // ValidatedMintConfigTx should be the identity function.
    fn test_convert_validated_mint_config() {
        let source = ValidatedMintConfigTx {
            mint_config_tx: MintConfigTx {
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
                    total_mint_limit: 20000,
                },
                signature: test_multi_sig(),
            },
            signer_set: test_signer_set(),
        };

        // decode(encode(source)) should be the identity function.
        {
            let bytes = encode(&source);
            let recovered = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }

        // Converting mc_transaction_core::mint::ValidatedMintConfigTx ->
        // external::ValidatedMintConfigTx -> mc_transaction_core::mint::
        // ValidatedMintConfigTx should be the identity function.
        {
            let external = external::ValidatedMintConfigTx::from(&source);
            let recovered = ValidatedMintConfigTx::try_from(&external).unwrap();
            assert_eq!(source, recovered);
        }

        // Encoding with prost, decoding with protobuf should be the identity
        // function.
        {
            let bytes = encode(&source);
            let recovered = external::ValidatedMintConfigTx::decode(bytes.as_slice()).unwrap();
            assert_eq!(recovered, external::ValidatedMintConfigTx::from(&source));
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external = external::ValidatedMintConfigTx::from(&source);
            let bytes = external.encode_to_vec();
            let recovered: ValidatedMintConfigTx = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }
    }
}
