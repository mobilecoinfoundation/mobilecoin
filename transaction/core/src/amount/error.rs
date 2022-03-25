//! Errors that can occur when handling an amount commitment.

use displaydoc::Display;

/// An error which can occur when handling an amount commitment.
#[derive(Debug, Display, Eq, PartialEq)]
pub enum AmountError {
    /**
     * The masked value, token id, or shared secret are not consistent with
     * the commitment.
     */
    InconsistentCommitment,
    /**
     * The masked token id has an invalid number of bytes
     */
    InvalidMaskedTokenId,
}
