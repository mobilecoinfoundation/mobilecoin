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
    mint::MintValidationError, ring_ct, ring_signature::Error as RingSignatureError,
    validation::TransactionValidationError as Error, BlockVersion, InputRuleError, TokenId,
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
            Error::InputRule(InputRuleError::MissingRequiredOutput) => {
                Self::InputRuleMissingRequiredOutput
            }
            Error::InputRule(InputRuleError::MaxTombstoneBlockExceeded) => {
                Self::InputRuleMaxTombstoneBlockExceeded
            }
        }
    }
}

/// Convert ProposeTxResult --> TransactionValidationError.
impl TryInto<Error> for ProposeTxResult {
    type Error = &'static str;

    fn try_into(self) -> Result<Error, Self::Error> {
        match self {
            Self::Ok => Err("Ok value cannot be convererted into TransactionValidationError"),
            Self::InputsProofsLengthMismatch => Ok(Error::InputsProofsLengthMismatch),
            Self::NoInputs => Ok(Error::NoInputs),
            Self::TooManyInputs => Ok(Error::TooManyInputs),
            Self::InsufficientInputSignatures => Ok(Error::InsufficientInputSignatures),
            Self::InvalidInputSignature => Ok(Error::InvalidInputSignature),
            Self::InvalidTransactionSignature => Ok(Error::InvalidTransactionSignature(
                ring_ct::Error::RingSignature(RingSignatureError::InvalidSignature),
            )),
            Self::InvalidRangeProof => Ok(Error::InvalidRangeProof),
            Self::InsufficientRingSize => Ok(Error::InsufficientRingSize),
            Self::TombstoneBlockExceeded => Ok(Error::TombstoneBlockExceeded),
            Self::TombstoneBlockTooFar => Ok(Error::TombstoneBlockTooFar),
            Self::NoOutputs => Ok(Error::NoOutputs),
            Self::TooManyOutputs => Ok(Error::TooManyOutputs),
            Self::ExcessiveRingSize => Ok(Error::ExcessiveRingSize),
            Self::DuplicateRingElements => Ok(Error::DuplicateRingElements),
            Self::UnsortedRingElements => Ok(Error::UnsortedRingElements),
            Self::UnequalRingSizes => Ok(Error::UnequalRingSizes),
            Self::UnsortedKeyImages => Ok(Error::UnsortedKeyImages),
            Self::ContainsSpentKeyImage => Ok(Error::ContainsSpentKeyImage),
            Self::DuplicateKeyImages => Ok(Error::DuplicateKeyImages),
            Self::DuplicateOutputPublicKey => Ok(Error::DuplicateOutputPublicKey),
            Self::ContainsExistingOutputPublicKey => Ok(Error::ContainsExistingOutputPublicKey),
            Self::MissingTxOutMembershipProof => Ok(Error::MissingTxOutMembershipProof),
            Self::InvalidTxOutMembershipProof => Ok(Error::InvalidTxOutMembershipProof),
            Self::InvalidRistrettoPublicKey => Ok(Error::InvalidRistrettoPublicKey),
            Self::InvalidLedgerContext => Ok(Error::InvalidLedgerContext),
            Self::Ledger => Ok(Error::Ledger(String::default())),
            Self::MembershipProofValidationError => Ok(Error::MembershipProofValidationError),
            Self::TxFeeError => Ok(Error::TxFeeError),
            Self::KeyError => Ok(Error::KeyError),
            Self::UnsortedInputs => Ok(Error::UnsortedInputs),
            Self::MissingMemo => Ok(Error::MissingMemo),
            Self::MemosNotAllowed => Ok(Error::MemosNotAllowed),
            Self::TokenNotYetConfigured => Ok(Error::TokenNotYetConfigured),
            Self::MissingMaskedTokenId => Ok(Error::MissingMaskedTokenId),
            Self::MaskedTokenIdNotAllowed => Ok(Error::MaskedTokenIdNotAllowed),
            Self::UnsortedOutputs => Ok(Error::UnsortedOutputs),
            Self::InputRulesNotAllowed => Ok(Error::InputRulesNotAllowed),
            Self::InputRuleMissingRequiredOutput => {
                Ok(Error::InputRule(InputRuleError::MissingRequiredOutput))
            }
            Self::InputRuleMaxTombstoneBlockExceeded => {
                Ok(Error::InputRule(InputRuleError::MaxTombstoneBlockExceeded))
            }
        }
    }
}

/// Convert MintValidationError -> MintValidationResult.
impl From<MintValidationError> for MintValidationResult {
    fn from(src: MintValidationError) -> Self {
        match src {
            MintValidationError::InvalidBlockVersion(block_version) => Self {
                code: MintValidationResultCode::InvalidBlockVersion as i32,
                block_version: *block_version,
                ..Default::default()
            },
            MintValidationError::InvalidTokenId(token_id) => Self {
                code: MintValidationResultCode::InvalidTokenId as i32,
                token_id: *token_id,
                ..Default::default()
            },
            MintValidationError::InvalidNonceLength(len) => Self {
                code: MintValidationResultCode::InvalidNonceLength as i32,
                nonce_length: len as u64,
                ..Default::default()
            },
            MintValidationError::InvalidSignerSet => Self {
                code: MintValidationResultCode::InvalidSignerSet as i32,
                ..Default::default()
            },
            MintValidationError::InvalidSignature => Self {
                code: MintValidationResultCode::InvalidSignature as i32,
                ..Default::default()
            },
            MintValidationError::TombstoneBlockExceeded => Self {
                code: MintValidationResultCode::TombstoneBlockExceeded as i32,
                ..Default::default()
            },
            MintValidationError::TombstoneBlockTooFar => Self {
                code: MintValidationResultCode::TombstoneBlockTooFar as i32,
                ..Default::default()
            },
            MintValidationError::Unknown => Self {
                code: MintValidationResultCode::Unknown as i32,
                ..Default::default()
            },
            MintValidationError::AmountExceedsMintLimit => Self {
                code: MintValidationResultCode::AmountExceedsMintLimit as i32,
                ..Default::default()
            },
            MintValidationError::NoGovernors(token_id) => Self {
                code: MintValidationResultCode::NoGovernors as i32,
                token_id: *token_id,
                ..Default::default()
            },
            MintValidationError::NonceAlreadyUsed => Self {
                code: MintValidationResultCode::NonceAlreadyUsed as i32,
                ..Default::default()
            },
            MintValidationError::NoMatchingMintConfig => Self {
                code: MintValidationResultCode::NoMatchingMintConfig as i32,
                ..Default::default()
            },
        }
    }
}

/// Convert MintValidationResult -> MintValidationError.
impl TryInto<MintValidationError> for MintValidationResult {
    type Error = String;

    fn try_into(self) -> Result<MintValidationError, Self::Error> {
        match self.code() {
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
        Self {
            mint_config: Some((&src.mint_config).into()),
            total_minted: src.total_minted,
        }
    }
}

/// Convert consensus_config::ActiveMintConfig -->
/// mc_ledger_db::ActiveMintConfig
impl TryFrom<&consensus_config::ActiveMintConfig> for mc_ledger_db::ActiveMintConfig {
    type Error = ConversionError;

    fn try_from(src: &consensus_config::ActiveMintConfig) -> Result<Self, Self::Error> {
        let mint_config = src
            .mint_config
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;
        Ok(Self {
            mint_config,
            total_minted: src.total_minted,
        })
    }
}

/// Convert mc_ledger_db::ActiveMintConfigs -->
/// consensus_config::ActiveMintConfigs
impl From<&mc_ledger_db::ActiveMintConfigs> for consensus_config::ActiveMintConfigs {
    fn from(src: &mc_ledger_db::ActiveMintConfigs) -> Self {
        Self {
            configs: src.configs.iter().map(Into::into).collect(),
            mint_config_tx: Some((&src.mint_config_tx).into()),
        }
    }
}

/// Convert consensus_config::ActiveMintConfigs -->
/// mc_ledger_db::ActiveMintConfigs
impl TryFrom<&consensus_config::ActiveMintConfigs> for mc_ledger_db::ActiveMintConfigs {
    type Error = ConversionError;

    fn try_from(src: &consensus_config::ActiveMintConfigs) -> Result<Self, Self::Error> {
        let configs = src
            .configs
            .iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;
        let mint_config_tx = src
            .mint_config_tx
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;
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
    use mc_util_serial::round_trip_message_and_conversion;
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

        round_trip_message_and_conversion::<
            mc_ledger_db::ActiveMintConfig,
            consensus_config::ActiveMintConfig,
        >(&source);
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

        round_trip_message_and_conversion::<
            mc_ledger_db::ActiveMintConfigs,
            consensus_config::ActiveMintConfigs,
        >(&source);
    }
}
