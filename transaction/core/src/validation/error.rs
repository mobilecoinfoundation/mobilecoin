// Copyright (c) 2018-2020 MobileCoin Inc.

use alloc::string::String;
use failure::Fail;
use mc_crypto_keys::KeyError;
use serde::{Deserialize, Serialize};

/// Type alias for transaction validation results.
pub type TransactionValidationResult<T> = Result<T, TransactionValidationError>;

/// Reasons why a single transaction may fail to be valid with respect to the current ledger.
#[derive(Clone, Debug, Eq, Fail, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum TransactionValidationError {
    /// Each input should have one membership proof.
    #[fail(display = "InputsProofsLengthMismatch")]
    InputsProofsLengthMismatch,

    /// A transaction must have at least one input.
    #[fail(display = "NoInputs")]
    NoInputs,

    /// A transaction must have no more than the maximum allowed number of inputs.
    #[fail(display = "TooManyInputs")]
    TooManyInputs,

    /// Each input must have a signature.
    #[fail(display = "InsufficientInputSignatures")]
    InsufficientInputSignatures,

    /// Each input must have a valid signature.
    #[fail(display = "InvalidInputSignature")]
    InvalidInputSignature,

    /// The transaction must have a valid RingCT signature.
    #[fail(display = "InvalidTransactionSignature")]
    InvalidTransactionSignature(#[fail(cause)] crate::ring_signature::Error),

    /// All Range Proofs in the transaction must be valid.
    #[fail(display = "InvalidRangeProof")]
    InvalidRangeProof,

    /// Each input must contain a ring with no fewer than the minimum number of elements.
    #[fail(display = "InsufficientRingSize")]
    InsufficientRingSize,

    /// Number of blocks in ledger exceeds the tombstone block number.
    #[fail(display = "TombstoneBlockExceeded")]
    TombstoneBlockExceeded,

    /// Tombstone block is too far in the future.
    #[fail(display = "TombstoneBlockTooFar")]
    TombstoneBlockTooFar,

    /// Must have at least one output.
    #[fail(display = "NoOutputs")]
    NoOutputs,

    /// A transaction must have no more than the maximum allowed number of outputs.
    #[fail(display = "TooManyOutputs")]
    TooManyOutputs,

    /// Each input must contain a ring with no more than the maximum number of elements.
    #[fail(display = "ExcessiveRingSize")]
    ExcessiveRingSize,

    /// All elements in all rings within the transaction must be unique.
    #[fail(display = "DuplicateRingElements")]
    DuplicateRingElements,

    /// The elements of each ring must be sorted.
    #[fail(display = "UnsortedRingElements")]
    UnsortedRingElements,

    /// All rings in a transaction must be of the same size.
    #[fail(display = "UnequalRingSizes")]
    UnequalRingSizes,

    /// Inputs must be sorted by the public key of the first ring element of each input.
    #[fail(display = "UnsortedInputs")]
    UnsortedInputs,

    /// Key Images must be sorted.
    #[fail(display = "UnsortedKeyImages")]
    UnsortedKeyImages,

    /// Contains a Key Image that has previously been spent.
    #[fail(display = "ContainsSpentKeyImage")]
    ContainsSpentKeyImage,

    /// Key Images within the transaction must be unique.
    #[fail(display = "DuplicateKeyImages")]
    DuplicateKeyImages,

    /// Output public keys in the transaction must be unique.
    #[fail(display = "DuplicateOutputPublicKey")]
    DuplicateOutputPublicKey,

    /// Contains an output public key that has previously appeared in the ledger.
    #[fail(display = "ContainsExistingOutputPublicKey")]
    ContainsExistingOutputPublicKey,

    /// Each ring element must have a corresponding proof of membership.
    #[fail(display = "MissingTxOutMembershipProof")]
    MissingTxOutMembershipProof,

    /// Each ring element must have a valid proof of membership.
    #[fail(display = "InvalidTxOutMembershipProof")]
    InvalidTxOutMembershipProof,

    /// Public keys must be valid Ristretto points.
    #[fail(display = "InvalidRistrettoPublicKey")]
    InvalidRistrettoPublicKey,

    /// Ledger context provided by the untrusted system is insufficient to validate the transaction.
    #[fail(display = "InvalidLedgerContext")]
    InvalidLedgerContext,

    /// Error querying the local ledger.
    #[fail(display = "Ledger DB error: {}", _0)]
    Ledger(String),

    /// An error occurred while validating a membership proof.
    #[fail(display = "MembershipProofValidationError")]
    MembershipProofValidationError,

    /// An error occurred while checking transaction fees.
    #[fail(display = "TxFeeError")]
    TxFeeError,

    /// Public keys must be valid Ristretto points.
    #[fail(display = "KeyError")]
    KeyError,
}

impl From<mc_crypto_keys::KeyError> for TransactionValidationError {
    fn from(_src: KeyError) -> Self {
        Self::KeyError
    }
}
