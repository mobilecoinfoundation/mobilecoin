// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Conversions between "API types" and "domain/persistence types".
//!
//! gRPC and Protobuf provide a reduced selection of types, and so there are
//! some differences between values stored in the ledger and values transmitted
//! over the API. This module provides conversions between "equivalent" types,
//! such as `mc_consensus_api::consensus_common::ProposeTxResult` and
//! `mc_transaction_core::validation::TransactionValidationError`.

use crate::consensus_common::ProposeTxResult;
use mc_transaction_core::{ring_signature, validation::TransactionValidationError as Error};
use std::convert::{From, TryInto};

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
            Error::UnsortedOutputs => Self::UnsortedOutputs,
            Error::MissingMemo => Self::MissingMemo,
            Error::MemosNotAllowed => Self::MemosNotAllowed,
            Error::TokenNotYetConfigured => Self::TokenNotYetConfigured,
            Error::MissingMaskedTokenId => Self::MissingMaskedTokenId,
            Error::MaskedTokenIdNotAllowed => Self::MaskedTokenIdNotAllowed,
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
            Self::UnsortedOutputs => Ok(Error::UnsortedOutputs),
            Self::MissingMemo => Ok(Error::MissingMemo),
            Self::MemosNotAllowed => Ok(Error::MemosNotAllowed),
            Self::TokenNotYetConfigured => Ok(Error::TokenNotYetConfigured),
            Self::MissingMaskedTokenId => Ok(Error::MissingMaskedTokenId),
            Self::MaskedTokenIdNotAllowed => Ok(Error::MaskedTokenIdNotAllowed),
        }
    }
}

#[cfg(test)]
mod conversion_tests {}
