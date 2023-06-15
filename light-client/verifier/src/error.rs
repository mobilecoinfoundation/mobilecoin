// Copyright (c) 2018-2023 The MobileCoin Foundation

use displaydoc::Display;
use mc_blockchain_types::{BlockContentsHash, BlockID, BlockIndex};

#[derive(Debug, Display)]
pub enum Error {
    /// The block metadata is not signing the expected block id: {0:?}
    BlockIdMismatch(BlockID),
    /// The block metadata signature could not be validated
    BlockMetadataSignature,
    /// Insufficient block signatures to form a quorum
    NotAQuorum,
    /// The block id does not match the block
    InvalidBlockId,
    /// No configured validator set for block index {0}, and id not allowlisted
    NoMatchingValidatorSet(BlockIndex),
    /// The block content hash does not match the block: {0:?}
    BlockContentHashMismatch(BlockContentsHash),
    /// TxOut (index {0}) was not found among the block contents
    TxOutNotFound(usize),
}
