// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Errors that can occur when handling an amount commitment.

use displaydoc::Display;
use serde::{Deserialize, Serialize};

/// An error which can occur when handling an amount commitment.
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

    /**
     * The masked amount is missing
     */
    MissingMaskedAmount,

    /// Token Id is not supported at this block version
    TokenIdNotSupportedAtBlockVersion,

    /// Amount is too old to have amount shared secret
    AmountTooOldForAmountSharedSecret,
}
