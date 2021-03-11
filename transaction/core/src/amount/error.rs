//! Errors that can occur when constructing an amount.

use displaydoc::Display;

#[derive(Debug, Display, Eq, PartialEq)]
pub enum AmountError {
    /**
     * The masked value, blinding, or shared secret are not consistent with
     * the commitment.
     */
    InconsistentCommitment,
}
