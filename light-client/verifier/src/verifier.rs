// Copyright (c) 2018-2023 The MobileCoin Foundation

use crate::{Error, TrustedValidatorSet};
use mc_blockchain_types::{Block, BlockContents, BlockID, BlockIndex, BlockMetadata};
use mc_transaction_core::tx::TxOut;
use std::{collections::HashSet, ops::Range};

/// The light client verifier
///
/// This object is capable of:
/// * Validating a Block given BlockMetadata containing node signatures
/// * Validating one or more TxOut's, that appeared in a given Block.
///
/// Without making network connections.
#[derive(Clone, Debug)]
pub struct LightClientVerifier {
    /// A quorum configuration and expected signing keys for the validator
    /// network.
    pub trusted_validator_set: TrustedValidatorSet,
    /// A block index before which this trusted validator set is not used
    pub trusted_validator_set_start_block: BlockIndex,
    /// A list of historical validator sets, and ranges of block indices at
    /// which they were valid
    pub historical_validator_sets: Vec<(Range<BlockIndex>, TrustedValidatorSet)>,
    /// A list of known valid block ids, which may appear before
    /// trusted_validator_set_start_block.
    pub known_valid_block_ids: HashSet<BlockID>,
}

// For a simple LightClientVerifier initialization
impl From<TrustedValidatorSet> for LightClientVerifier {
    fn from(src: TrustedValidatorSet) -> Self {
        Self {
            trusted_validator_set: src,
            trusted_validator_set_start_block: 0,
            historical_validator_sets: Default::default(),
            known_valid_block_ids: Default::default(),
        }
    }
}

impl LightClientVerifier {
    /// Validate that a given block has been externalized by the network, given
    /// additional evidence in the form of BlockMetadata with signatures.
    pub fn validate_block(&self, block: &Block, metadata: &[BlockMetadata]) -> Result<(), Error> {
        if !block.is_block_id_valid() {
            return Err(Error::InvalidBlockId);
        }
        if self.known_valid_block_ids.contains(&block.id) {
            return Ok(());
        }
        if block.index >= self.trusted_validator_set_start_block {
            let metadata_block_id = self
                .trusted_validator_set
                .validate_block_id_signatures(metadata)?;
            if metadata_block_id != block.id {
                return Err(Error::BlockIdMismatch);
            }
            return Ok(());
        }

        for (range, validator_set) in self.historical_validator_sets.iter() {
            if range.contains(&block.index) {
                let metadata_block_id = validator_set.validate_block_id_signatures(metadata)?;
                if metadata_block_id != block.id {
                    return Err(Error::BlockIdMismatch);
                }
                return Ok(());
            }
        }
        Error::NoMatchingValidatorSet
    }

    /// Validate that a given block has been externalized, and that it matches
    /// to given block contents
    pub fn validate_block_and_block_contents(
        &self,
        block: &Block,
        block_contents: &BlockContents,
        block_metadata: &[BlockMetadata],
    ) -> Result<(), Error> {
        // Validate the block
        self.validate_block(block, block_metadata)?;
        // Validate that the contents match the block
        let contents_hash = block_contents.hash();
        if contents_hash != block.contents_hash {
            return Err(Error::BlockContentHashMismatch);
        }
        Ok(())
    }

    /// Validate that one or more TxOut's appeared in a particular block that
    /// was externalized
    pub fn validate_txos_in_block(
        &self,
        txos: &[TxOut],
        block: &Block,
        block_contents: &BlockContents,
        block_metadata: &[BlockMetadata],
    ) -> Result<(), Error> {
        // Validate the block and block contents
        self.validate_block_and_block_contents(block, block_contents, block_metadata)?;
        // Validate that each Txo actually appears in the block.
        // Note: for big enough blocks, it's probably faster to throw them in a hash set
        // first, but it has to be very big for this to be noticeable.
        for txo in txos {
            if !block_contents
                .outputs
                .iter()
                .any(|block_contents_txo| block_contents_txo == txo)
            {
                return Err(Error::TxOutNotFound);
            }
        }
        Ok(())
    }
}
