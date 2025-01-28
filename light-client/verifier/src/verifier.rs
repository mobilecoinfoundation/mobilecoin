// Copyright (c) 2018-2023 The MobileCoin Foundation

use crate::{Error, TrustedValidatorSet};
use mc_blockchain_types::{Block, BlockContents, BlockData, BlockID, BlockIndex, BlockMetadata};
use mc_transaction_core::tx::TxOut;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, ops::Range};

/// The light client verifier
///
/// This object is capable of:
/// * Verifying a Block given BlockMetadata containing node signatures
/// * Verifying one or more TxOut's, that appeared in a given Block.
///
/// The verifier does not make network connections and its state does not
/// change when it verifies things. It needs to be configured with correct
/// trusted validator sets to give give correct results.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LightClientVerifier {
    /// A quorum configuration and expected signing keys for the validator
    /// network.
    pub trusted_validator_set: TrustedValidatorSet,
    /// The first block index at which this trusted validator set is applied.
    pub trusted_validator_set_start_block: BlockIndex,
    /// A list of historical validator sets, and ranges of block indices at
    /// which they should be used.
    ///
    /// Note: There can only be one correct TrustedValidatorSet for a given
    /// block index, the light client verifier should not accept blocks from
    /// two different forks. It is a precondition violation if these ranges
    /// overlap or extend past trusted_validator_set_start_block.
    pub historical_validator_sets: Vec<(Range<BlockIndex>, TrustedValidatorSet)>,
    /// A list of known valid block ids, which may appear before
    /// `trusted_validator_set_start_block` and outside of any of the historical
    /// ranges.
    pub known_valid_block_ids: BTreeSet<BlockID>,
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
    /// Verify that a given block has been externalized by the network, given
    /// additional evidence in the form of BlockMetadata with signatures,
    /// relative to our configuration of trusted validator sets.
    pub fn verify_block(&self, block: &Block, metadata: &[BlockMetadata]) -> Result<(), Error> {
        if !block.is_block_id_valid() {
            return Err(Error::InvalidBlockId);
        }
        if self.known_valid_block_ids.contains(&block.id) {
            return Ok(());
        }
        if block.index >= self.trusted_validator_set_start_block {
            return self
                .trusted_validator_set
                .verify_block_id_signatures(&block.id, metadata);
        }

        for (range, validator_set) in self.historical_validator_sets.iter() {
            if range.contains(&block.index) {
                return validator_set.verify_block_id_signatures(&block.id, metadata);
            }
        }
        Err(Error::NoMatchingValidatorSet(block.index))
    }

    /// Verify that a given block has been externalized, and that it matches
    /// to given block contents.
    pub fn verify_block_and_block_contents(
        &self,
        block: &Block,
        block_contents: &BlockContents,
        block_metadata: &[BlockMetadata],
    ) -> Result<(), Error> {
        self.verify_block(block, block_metadata)?;
        // Verify that the contents match the block
        let contents_hash = block_contents.hash();
        if contents_hash != block.contents_hash {
            return Err(Error::BlockContentHashMismatch(contents_hash));
        }
        Ok(())
    }

    /// Verify that one or more TxOut's appeared in a particular block that
    /// was externalized
    pub fn verify_txos_in_block(
        &self,
        txos: &[TxOut],
        block: &Block,
        block_contents: &BlockContents,
        block_metadata: &[BlockMetadata],
    ) -> Result<(), Error> {
        self.verify_block_and_block_contents(block, block_contents, block_metadata)?;
        // Verify that each Txo actually appears in the block.
        // Note: for big enough blocks, it's probably faster to throw them in a hash set
        // first, but it has to be very big for this to be noticeable.
        for txo in txos.iter() {
            if !block_contents
                .outputs
                .iter()
                .any(|block_contents_txo| block_contents_txo == txo)
            {
                return Err(Error::TxOutNotFound(*txo.public_key.as_bytes()));
            }
        }
        Ok(())
    }

    /// Verify that a list of BlockDatas all contain the same block and
    /// block_contents, and that the block was externalized given evidence in
    /// the BlockMetadata available.
    pub fn verify_block_data(
        &self,
        block_data: &[BlockData],
    ) -> Result<(Block, BlockContents), Error> {
        if block_data.is_empty() {
            return Err(Error::NoBlockData);
        }

        // All block_data should point at the same block/block_contents.
        if !block_data
            .windows(2)
            .all(|w| w[0].block() == w[1].block() && w[0].contents() == w[1].contents())
        {
            return Err(Error::BlockDataMismatch);
        }

        let block = block_data[0].block();
        let block_contents = block_data[0].contents();

        let block_metadata = block_data
            .iter()
            .filter_map(|block_data| block_data.metadata().cloned())
            .collect::<Vec<_>>();
        self.verify_block_and_block_contents(block, block_contents, &block_metadata[..])?;

        Ok((block.clone(), block_contents.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trusted_validator_set::tests::*;
    use core::assert_matches::assert_matches;
    use mc_consensus_scp_types::{test_utils::test_node_id, QuorumSet, QuorumSetMember};
    use mc_transaction_core::{encrypted_fog_hint::EncryptedFogHint, Amount};
    use mc_util_from_random::FromRandom;
    use mc_util_test_helper::get_seeded_rng;

    fn get_light_client_verifier(known_valid_block_ids: BTreeSet<BlockID>) -> LightClientVerifier {
        let current_tvs = TrustedValidatorSet {
            quorum_set: QuorumSet::new(
                3,
                vec![
                    QuorumSetMember::Node(test_node_id(1)),
                    QuorumSetMember::Node(test_node_id(2)),
                    QuorumSetMember::Node(test_node_id(3)),
                    QuorumSetMember::Node(test_node_id(4)),
                    QuorumSetMember::Node(test_node_id(5)),
                ],
            ),
        };

        let old_tvs = TrustedValidatorSet {
            quorum_set: QuorumSet::new(
                2,
                vec![
                    QuorumSetMember::Node(test_node_id(1)),
                    QuorumSetMember::Node(test_node_id(2)),
                    QuorumSetMember::Node(test_node_id(3)),
                ],
            ),
        };

        LightClientVerifier {
            trusted_validator_set: current_tvs,
            trusted_validator_set_start_block: 10_000,
            historical_validator_sets: vec![((5_000..10_000), old_tvs)],
            known_valid_block_ids,
        }
    }

    #[test]
    fn test_verify_block() {
        let block88 = Block::new(
            Default::default(),
            &Default::default(),
            88,
            88,
            &Default::default(),
            &Default::default(),
        );

        let lcv = get_light_client_verifier(BTreeSet::from([block88.id.clone()]));

        let block99 = Block::new(
            Default::default(),
            &Default::default(),
            99,
            99,
            &Default::default(),
            &Default::default(),
        );
        let block9999 = Block::new(
            Default::default(),
            &Default::default(),
            9999,
            9999,
            &Default::default(),
            &Default::default(),
        );
        let block99999 = Block::new(
            Default::default(),
            &Default::default(),
            99999,
            99999,
            &Default::default(),
            &Default::default(),
        );

        // Block 88 verifies even without any signatures, because we put it in the
        // known-valid list.
        lcv.verify_block(&block88, &[]).unwrap();
        lcv.verify_block(
            &block88,
            &sign_block_id_for_test_node_ids(&block99.id, &[1, 2]),
        )
        .unwrap();
        lcv.verify_block(
            &block88,
            &sign_block_id_for_test_node_ids(&block99.id, &[4, 5]),
        )
        .unwrap();
        lcv.verify_block(
            &block88,
            &sign_block_id_for_test_node_ids(&block99.id, &[1, 2, 3]),
        )
        .unwrap();

        // Block 99 doesn't verify with any number of signatures, because it's not known
        // to be valid and is outside all ranges
        assert_matches!(
            lcv.verify_block(&block99, &[]),
            Err(Error::NoMatchingValidatorSet(99))
        );
        assert_matches!(
            lcv.verify_block(
                &block99,
                &sign_block_id_for_test_node_ids(&block99.id, &[1, 2])
            ),
            Err(Error::NoMatchingValidatorSet(99))
        );
        assert_matches!(
            lcv.verify_block(
                &block99,
                &sign_block_id_for_test_node_ids(&block99.id, &[4, 5])
            ),
            Err(Error::NoMatchingValidatorSet(99))
        );
        assert_matches!(
            lcv.verify_block(
                &block99,
                &sign_block_id_for_test_node_ids(&block99.id, &[1, 2, 3])
            ),
            Err(Error::NoMatchingValidatorSet(99))
        );

        // Block 9999 needs two signatures of [1, 2, 3], because it belongs to the old
        // tvs
        assert_matches!(lcv.verify_block(&block9999, &[]), Err(Error::NotAQuorum));
        lcv.verify_block(
            &block9999,
            &sign_block_id_for_test_node_ids(&block9999.id, &[1, 2]),
        )
        .unwrap();
        assert_matches!(
            lcv.verify_block(
                &block9999,
                &sign_block_id_for_test_node_ids(&block9999.id, &[4, 5])
            ),
            Err(Error::NotAQuorum)
        );
        lcv.verify_block(
            &block9999,
            &sign_block_id_for_test_node_ids(&block9999.id, &[1, 2, 3]),
        )
        .unwrap();

        // Block 99999 needs three signatures, because it belongs to the new tvs
        assert_matches!(lcv.verify_block(&block99999, &[]), Err(Error::NotAQuorum));
        assert_matches!(
            lcv.verify_block(
                &block99999,
                &sign_block_id_for_test_node_ids(&block99999.id, &[1, 2])
            ),
            Err(Error::NotAQuorum)
        );
        assert_matches!(
            lcv.verify_block(
                &block99999,
                &sign_block_id_for_test_node_ids(&block99999.id, &[4, 5])
            ),
            Err(Error::NotAQuorum)
        );
        lcv.verify_block(
            &block99999,
            &sign_block_id_for_test_node_ids(&block99999.id, &[1, 2, 3]),
        )
        .unwrap();
    }

    #[test]
    fn test_verify_txos_in_block() {
        let mut rng = get_seeded_rng();

        let lcv = get_light_client_verifier(Default::default());

        let txo1 = TxOut::new(
            Default::default(),
            Amount::new(1, 0.into()),
            &FromRandom::from_random(&mut rng),
            &FromRandom::from_random(&mut rng),
            EncryptedFogHint::fake_onetime_hint(&mut rng),
        )
        .unwrap();

        let txo2 = TxOut::new(
            Default::default(),
            Amount::new(2, 0.into()),
            &FromRandom::from_random(&mut rng),
            &FromRandom::from_random(&mut rng),
            EncryptedFogHint::fake_onetime_hint(&mut rng),
        )
        .unwrap();

        let txo3 = TxOut::new(
            Default::default(),
            Amount::new(2, 0.into()),
            &FromRandom::from_random(&mut rng),
            &FromRandom::from_random(&mut rng),
            EncryptedFogHint::fake_onetime_hint(&mut rng),
        )
        .unwrap();

        let bc = BlockContents {
            outputs: vec![txo1.clone(), txo2.clone()],
            ..Default::default()
        };

        let block9999 = Block::new(
            Default::default(),
            &Default::default(),
            9999,
            9999,
            &Default::default(),
            &bc,
        );

        let metadata = sign_block_id_for_test_node_ids(&block9999.id, &[1, 2, 3]);

        // We can verify that these block contents are correct
        lcv.verify_block_and_block_contents(&block9999, &bc, &metadata)
            .unwrap();

        // We cannot verify that different block contents are correct
        assert_matches!(
            lcv.verify_block_and_block_contents(&block9999, &BlockContents::default(), &metadata,),
            Err(Error::BlockContentHashMismatch(_))
        );

        // We can verify that txo1 is in the block
        lcv.verify_txos_in_block(&[txo1.clone()], &block9999, &bc, &metadata)
            .unwrap();

        // We can verify that txo2 is in the block
        lcv.verify_txos_in_block(&[txo2.clone()], &block9999, &bc, &metadata)
            .unwrap();

        // We can verify that txo1 and txo2 are in the block
        lcv.verify_txos_in_block(&[txo1.clone(), txo2.clone()], &block9999, &bc, &metadata)
            .unwrap();

        // We cannot verify that all three are in the block
        assert_matches!(
            lcv.verify_txos_in_block(
                &[txo1.clone(), txo2.clone(), txo3.clone()],
                &block9999,
                &bc,
                &metadata,
            ),
            Err(Error::TxOutNotFound(_))
        );

        // We cannot verify that txo3 is in the block
        assert_matches!(
            lcv.verify_txos_in_block(&[txo3.clone()], &block9999, &bc, &metadata,),
            Err(Error::TxOutNotFound(_))
        );

        // Suppress clippies
        drop(txo1);
        drop(txo2);
        drop(txo3);
    }

    #[test]
    fn test_verify_block_data() {
        let mut rng = get_seeded_rng();

        let lcv = get_light_client_verifier(Default::default());

        let txo1 = TxOut::new(
            Default::default(),
            Amount::new(1, 0.into()),
            &FromRandom::from_random(&mut rng),
            &FromRandom::from_random(&mut rng),
            EncryptedFogHint::fake_onetime_hint(&mut rng),
        )
        .unwrap();

        let txo2 = TxOut::new(
            Default::default(),
            Amount::new(2, 0.into()),
            &FromRandom::from_random(&mut rng),
            &FromRandom::from_random(&mut rng),
            EncryptedFogHint::fake_onetime_hint(&mut rng),
        )
        .unwrap();

        let txo3 = TxOut::new(
            Default::default(),
            Amount::new(2, 0.into()),
            &FromRandom::from_random(&mut rng),
            &FromRandom::from_random(&mut rng),
            EncryptedFogHint::fake_onetime_hint(&mut rng),
        )
        .unwrap();

        let bc = BlockContents {
            outputs: vec![txo1, txo2],
            ..Default::default()
        };

        let block9999 = Block::new(
            Default::default(),
            &Default::default(),
            9999,
            9999,
            &Default::default(),
            &bc,
        );

        let metadata = sign_block_id_for_test_node_ids(&block9999.id, &[1, 2, 3]);

        let block_datas = metadata
            .into_iter()
            .map(|metadata| BlockData::new(block9999.clone(), bc.clone(), None, Some(metadata)))
            .collect::<Vec<_>>();

        // Calling verify_block_data without any block data returns an error.
        assert_matches!(lcv.verify_block_data(&[]), Err(Error::NoBlockData));

        // Calling verify_block_data with block data that differs from each other
        // returns an error.
        let different_block_data = block_datas[0].clone();
        let different_block_data =
            different_block_data.mutate(|_, contents, _, _| contents.outputs.push(txo3));

        assert_matches!(
            lcv.verify_block_data(&[block_datas[0].clone(), different_block_data]),
            Err(Error::BlockDataMismatch)
        );

        // Passing the correct block metadata verifies successfully and returns the
        // block and its contents.
        let (block, block_contents) = lcv.verify_block_data(&block_datas[..]).unwrap();

        assert_eq!(block, block9999);
        assert_eq!(block_contents, bc);

        // Omitting one of the block data entries should still succeed since we need 2
        // out of 3.
        let (block, block_contents) = lcv.verify_block_data(&block_datas[1..]).unwrap();

        assert_eq!(block, block9999);
        assert_eq!(block_contents, bc);

        // Omitting two of the block data entries should fail since we need 2 out of 3.
        assert_matches!(
            lcv.verify_block_data(&block_datas[2..]),
            Err(Error::NotAQuorum)
        );
    }
}
