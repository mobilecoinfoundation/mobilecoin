// Copyright (c) 2018-2023 The MobileCoin Foundation

use displaydoc::Display;

#[derive(Debug, Display)]
pub enum Error {
    /// At least one block metadata object is needed to form a quorum.
    NoBlockMetadata,
    /// The block metadata are not all signing the same block id
    BlockIdMismatch,
    /// The block signature could not be validated
    BlockSignature,
    /// Insufficient block signatures to form a quorum
    NotAQuorum,
    /// The block id does not match the block
    InvalidBlockId,
    /// No configured validator set for this block index, and id not whitelisted
    NoMatchingValidatorSet,
    /// The block content hash does not match the block
    BlockContentHashMismatch,
    /// A TxOut was not found amongst the block contents
    TxOutNotFound,
}
