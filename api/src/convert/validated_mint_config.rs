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
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;
        let signer_set = source
            .signer_set
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
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
    use mc_util_serial::round_trip_message;

    #[test]
    // ValidatedMintConfigTx -> external::ValidatedMintConfigTx ->
    // ValidatedMintConfigTx should be the identity function.
    fn round_trip() {
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

        round_trip_message::<ValidatedMintConfigTx, external::ValidatedMintConfigTx>(&source);
    }
}
