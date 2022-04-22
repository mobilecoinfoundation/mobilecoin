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
};
use mc_transaction_core::{
    mint::MintValidationError, ring_signature, validation::TransactionValidationError as Error,
    BlockVersion, TokenId,
};
use std::convert::{From, TryFrom, TryInto};

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
                ring_signature::Error::InvalidSignature,
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

#[cfg(test)]
mod conversion_tests {}
