// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Conversions between "API types" and "domain/persistence types".
//!
//! gRPC and Protobuf provide a reduced selection of types, and so there are
//! some differences between values stored in the ledger and values transmitted
//! over the API. This module provides conversions between "equivalent" types,
//! such as `mc_consensus_api::consensus_common::ProposeTxResult` and
//! `mc_transaction_core::validation::TransactionValidationError`.

use crate::{
    consensus_client::{MintValidationResult, MintValidationResultCode},
    consensus_common::ProposeTxResult,
    consensus_config,
};
use mc_api::ConversionError;
use mc_transaction_core::{
    mint::MintValidationError, validation::TransactionValidationError as Error, BlockVersion,
    InputRuleError, TokenId,
};

/// Convert TransactionValidationError --> ProposeTxResult.
impl From<Error> for ProposeTxResult {
    fn from(src: Error) -> Self {
        match src {
            Error::InputsProofsLengthMismatch => Self::InputsProofsLengthMismatch,
            Error::NoInputs => Self::NoInputs,
            Error::TooManyInputs => Self::TooManyInputs,
            Error::InsufficientInputSignatures => Self::InsufficientInputSignatures,
            Error::InvalidInputSignature => Self::InvalidInputSignature,
            Error::InvalidTransactionSignature(_e) => Self::InvalidTransactionSignature,
            Error::InvalidRangeProof => Self::InvalidRangeProof,
            Error::InsufficientRingSize => Self::InsufficientRingSize,
            Error::TombstoneBlockExceeded => Self::TombstoneBlockExceeded,
            Error::TombstoneBlockTooFar => Self::TombstoneBlockTooFar,
            Error::NoOutputs => Self::NoOutputs,
            Error::TooManyOutputs => Self::TooManyOutputs,
            Error::ExcessiveRingSize => Self::ExcessiveRingSize,
            Error::DuplicateRingElements => Self::DuplicateRingElements,
            Error::UnsortedRingElements => Self::UnsortedRingElements,
            Error::UnequalRingSizes => Self::UnequalRingSizes,
            Error::UnsortedKeyImages => Self::UnsortedKeyImages,
            Error::ContainsSpentKeyImage => Self::ContainsSpentKeyImage,
            Error::DuplicateKeyImages => Self::DuplicateKeyImages,
            Error::DuplicateOutputPublicKey => Self::DuplicateOutputPublicKey,
            Error::ContainsExistingOutputPublicKey => Self::ContainsExistingOutputPublicKey,
            Error::MissingTxOutMembershipProof => Self::MissingTxOutMembershipProof,
            Error::InvalidTxOutMembershipProof => Self::InvalidTxOutMembershipProof,
            Error::InvalidRistrettoPublicKey => Self::InvalidRistrettoPublicKey,
            Error::InvalidLedgerContext => Self::InvalidLedgerContext,
            Error::Ledger(_) => Self::Ledger,
            Error::MembershipProofValidationError => Self::MembershipProofValidationError,
            Error::TxFeeError => Self::TxFeeError,
            Error::KeyError => Self::KeyError,
            Error::UnsortedInputs => Self::UnsortedInputs,
            Error::MissingMemo => Self::MissingMemo,
            Error::MemosNotAllowed => Self::MemosNotAllowed,
            Error::TokenNotYetConfigured => Self::TokenNotYetConfigured,
            Error::MissingMaskedTokenId => Self::MissingMaskedTokenId,
            Error::MaskedTokenIdNotAllowed => Self::MaskedTokenIdNotAllowed,
            Error::UnsortedOutputs => Self::UnsortedOutputs,
            Error::InputRulesNotAllowed => Self::InputRulesNotAllowed,
            Error::InputRule(ir) => {
                match ir {
                    InputRuleError::MissingRequiredOutput => Self::InputRuleMissingRequiredOutput,
                    InputRuleError::MaxTombstoneBlockExceeded =>
                        Self::InputRuleMaxTombstoneBlockExceeded,
                    InputRuleError::FractionalOutputsNotExpected => Self::InputRuleFractionalOutputsNotExpected,
                    InputRuleError::ChangeOutputSharedSecretNotExpected => Self::InputRuleChangeOutputSharedSecretNotExpected,
                    InputRuleError::MaxAllowedChangeValueNotExpected => Self::InputRuleMaxAlowedChangeValueNotExpected,
                    InputRuleError::MissingRealChangeOutput => Self::InputRuleMissingRealChangeOutput,
                    InputRuleError::MissingChangeOutputSharedSecret => Self::InputRuleMissingChangeOutputSharedSecret,
                    InputRuleError::WrongNumberOfAmountSharedSecrets => Self::InputRuleWrongNumberOfAmountSharedSecrets,
                    InputRuleError::MissingRealOutput => Self::InputRuleMissingRealOutput,
                    InputRuleError::RealOutputTokenIdMismatch => Self::InputRuleRealOutputTokenIdMismatch,
                    InputRuleError::RealOutputAmountExceedsFractional => Self::InputRuleRealOutputAmountExceedsFractional,
                    InputRuleError::RealOutputAmountDoesNotRespectFillFraction => Self::InputRuleRealOutputAmountDoesNotRespectFillFraction,
                    InputRuleError::RealChangeOutputAmountExceedsLimit => Self::InputRuleRealChangeOutputAmountExceedsLimit,
                    InputRuleError::InvalidAmountSharedSecret => Self::InputRuleInvalidAmountSharedSecret,
                    InputRuleError::TxOutConversion(_) => Self::InputRuleTxOutConversion,
                    InputRuleError::Amount(_) => Self::InputRuleAmount,                    
                }
            }
            Error::UnknownMaskedAmountVersion => Self::UnknownMaskedAmountVersion,
        }
    }
}

/// Convert MintValidationError -> MintValidationResult.
impl From<MintValidationError> for MintValidationResult {
    fn from(src: MintValidationError) -> Self {
        match src {
            MintValidationError::InvalidBlockVersion(block_version) => Self {
                code: MintValidationResultCode::InvalidBlockVersion,
                block_version: *block_version,
                ..Default::default()
            },
            MintValidationError::InvalidTokenId(token_id) => Self {
                code: MintValidationResultCode::InvalidTokenId,
                token_id: *token_id,
                ..Default::default()
            },
            MintValidationError::InvalidNonceLength(len) => Self {
                code: MintValidationResultCode::InvalidNonceLength,
                nonce_length: len as u64,
                ..Default::default()
            },
            MintValidationError::InvalidSignerSet => Self {
                code: MintValidationResultCode::InvalidSignerSet,
                ..Default::default()
            },
            MintValidationError::InvalidSignature => Self {
                code: MintValidationResultCode::InvalidSignature,
                ..Default::default()
            },
            MintValidationError::TombstoneBlockExceeded => Self {
                code: MintValidationResultCode::TombstoneBlockExceeded,
                ..Default::default()
            },
            MintValidationError::TombstoneBlockTooFar => Self {
                code: MintValidationResultCode::TombstoneBlockTooFar,
                ..Default::default()
            },
            MintValidationError::Unknown => Self {
                code: MintValidationResultCode::Unknown,
                ..Default::default()
            },
            MintValidationError::AmountExceedsMintLimit => Self {
                code: MintValidationResultCode::AmountExceedsMintLimit,
                ..Default::default()
            },
            MintValidationError::NoGovernors(token_id) => Self {
                code: MintValidationResultCode::NoGovernors,
                token_id: *token_id,
                ..Default::default()
            },
            MintValidationError::NonceAlreadyUsed => Self {
                code: MintValidationResultCode::NonceAlreadyUsed,
                ..Default::default()
            },
            MintValidationError::NoMatchingMintConfig => Self {
                code: MintValidationResultCode::NoMatchingMintConfig,
                ..Default::default()
            },
        }
    }
}

/// Convert MintValidationResult -> MintValidationError.
impl TryInto<MintValidationError> for MintValidationResult {
    type Error = String;

    fn try_into(self) -> Result<MintValidationError, Self::Error> {
        match self.code {
            MintValidationResultCode::Ok => {
                Err("Ok value cannot be converted into MintValidationError".to_string())
            }
            MintValidationResultCode::InvalidBlockVersion => {
                Ok(MintValidationError::InvalidBlockVersion(
                    BlockVersion::try_from(self.block_version).map_err(|err| err.to_string())?,
                ))
            }
            MintValidationResultCode::InvalidTokenId => {
                Ok(MintValidationError::InvalidTokenId(self.token_id.into()))
            }
            MintValidationResultCode::InvalidNonceLength => Ok(
                MintValidationError::InvalidNonceLength(self.nonce_length as usize),
            ),
            MintValidationResultCode::InvalidSignerSet => Ok(MintValidationError::InvalidSignerSet),
            MintValidationResultCode::InvalidSignature => Ok(MintValidationError::InvalidSignature),
            MintValidationResultCode::TombstoneBlockExceeded => {
                Ok(MintValidationError::TombstoneBlockExceeded)
            }
            MintValidationResultCode::TombstoneBlockTooFar => {
                Ok(MintValidationError::TombstoneBlockTooFar)
            }
            MintValidationResultCode::Unknown => Ok(MintValidationError::Unknown),
            MintValidationResultCode::AmountExceedsMintLimit => {
                Ok(MintValidationError::AmountExceedsMintLimit)
            }
            MintValidationResultCode::NoGovernors => Ok(MintValidationError::NoGovernors(
                TokenId::from(self.token_id),
            )),
            MintValidationResultCode::NonceAlreadyUsed => Ok(MintValidationError::NonceAlreadyUsed),
            MintValidationResultCode::NoMatchingMintConfig => {
                Ok(MintValidationError::NoMatchingMintConfig)
            }
        }
    }
}

/// Convert mc_ledger_db::ActiveMintConfig -->
/// consensus_config::ActiveMintConfig
impl From<&mc_ledger_db::ActiveMintConfig> for consensus_config::ActiveMintConfig {
    fn from(src: &mc_ledger_db::ActiveMintConfig) -> Self {
        let mut dst = Self::new();
        dst.set_mint_config((&src.mint_config).into());
        dst.set_total_minted(src.total_minted);
        dst
    }
}

/// Convert consensus_config::ActiveMintConfig -->
/// mc_ledger_db::ActiveMintConfig
impl TryFrom<&consensus_config::ActiveMintConfig> for mc_ledger_db::ActiveMintConfig {
    type Error = ConversionError;

    fn try_from(src: &consensus_config::ActiveMintConfig) -> Result<Self, Self::Error> {
        let mint_config = src.get_mint_config().try_into()?;
        Ok(Self {
            mint_config,
            total_minted: src.get_total_minted(),
        })
    }
}

/// Convert mc_ledger_db::ActiveMintConfigs -->
/// consensus_config::ActiveMintConfigs
impl From<&mc_ledger_db::ActiveMintConfigs> for consensus_config::ActiveMintConfigs {
    fn from(src: &mc_ledger_db::ActiveMintConfigs) -> Self {
        let mut dst = Self::new();
        dst.set_configs(src.configs.iter().map(|config| config.into()).collect());
        dst.set_mint_config_tx((&src.mint_config_tx).into());
        dst
    }
}

/// Convert consensus_config::ActiveMintConfigs -->
/// mc_ledger_db::ActiveMintConfigs
impl TryFrom<&consensus_config::ActiveMintConfigs> for mc_ledger_db::ActiveMintConfigs {
    type Error = ConversionError;

    fn try_from(src: &consensus_config::ActiveMintConfigs) -> Result<Self, Self::Error> {
        let configs = src
            .get_configs()
            .iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;
        let mint_config_tx = src.get_mint_config_tx().try_into()?;
        Ok(Self {
            configs,
            mint_config_tx,
        })
    }
}

#[cfg(test)]
mod conversion_tests {
    use super::*;
    use mc_crypto_multisig::SignerSet;
    use mc_transaction_core::mint::MintConfig;
    use mc_transaction_core_test_utils::create_mint_config_tx_and_signers;
    use mc_util_serial::{decode, encode};
    use protobuf::Message;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    #[test]
    fn test_convert_active_mint_config() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let (_mint_config_tx, signers) = create_mint_config_tx_and_signers(2.into(), &mut rng);
        let signer_set = SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1);

        let source = mc_ledger_db::ActiveMintConfig {
            mint_config: MintConfig {
                token_id: 123,
                signer_set,
                mint_limit: 10000,
            },
            total_minted: 102,
        };

        // decode(encode(source)) should be the identity function.
        {
            let bytes = encode(&source);
            let recovered = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }

        // Converting mc_ledger_db::ActiveMintConfig ->
        // consensus_config::ActiveMintConfig -> mc_ledger_db::ActiveMintConfig
        // should be the identity function.
        {
            let external = consensus_config::ActiveMintConfig::from(&source);
            let recovered = mc_ledger_db::ActiveMintConfig::try_from(&external).unwrap();
            assert_eq!(source, recovered);
        }

        // Encoding with prost, decoding with protobuf should be the identity
        // function.
        {
            let bytes = encode(&source);
            let recovered = consensus_config::ActiveMintConfig::parse_from_bytes(&bytes).unwrap();
            assert_eq!(recovered, consensus_config::ActiveMintConfig::from(&source));
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external = consensus_config::ActiveMintConfig::from(&source);
            let bytes = external.write_to_bytes().unwrap();
            let recovered: mc_ledger_db::ActiveMintConfig = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }
    }

    #[test]
    fn test_convert_active_mint_configs() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(2.into(), &mut rng);
        let signer_set = SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1);

        let source = mc_ledger_db::ActiveMintConfigs {
            configs: vec![mc_ledger_db::ActiveMintConfig {
                mint_config: MintConfig {
                    token_id: 123,
                    signer_set,
                    mint_limit: 10000,
                },
                total_minted: 102,
            }],
            mint_config_tx,
        };

        // decode(encode(source)) should be the identity function.
        {
            let bytes = encode(&source);
            let recovered = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }

        // Converting mc_ledger_db::ActiveMintConfigs ->
        // consensus_config::ActiveMintConfigs -> mc_ledger_db::ActiveMintConfigs
        // should be the identity function.
        {
            let external = consensus_config::ActiveMintConfigs::from(&source);
            let recovered = mc_ledger_db::ActiveMintConfigs::try_from(&external).unwrap();
            assert_eq!(source, recovered);
        }

        // Encoding with prost, decoding with protobuf should be the identity
        // function.
        {
            let bytes = encode(&source);
            let recovered = consensus_config::ActiveMintConfigs::parse_from_bytes(&bytes).unwrap();
            assert_eq!(
                recovered,
                consensus_config::ActiveMintConfigs::from(&source)
            );
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external = consensus_config::ActiveMintConfigs::from(&source);
            let bytes = external.write_to_bytes().unwrap();
            let recovered: mc_ledger_db::ActiveMintConfigs = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }
    }
}
