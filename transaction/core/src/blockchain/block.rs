// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{
    tx::{TxOut, TxOutMembershipElement},
    BlockContents, BlockContentsHash, BlockID,
};
use alloc::vec::Vec;
use mc_crypto_digestible::{DigestTranscript, Digestible, MerlinTranscript};
use prost::Message;
use serde::{Deserialize, Serialize};

/// The current block format version.
pub const BLOCK_VERSION: u32 = 1;

/// The index of a block in the blockchain.
pub type BlockIndex = u64;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Digestible, Message)]
/// A block of transactions in the blockchain.
pub struct Block {
    /// Block ID.
    #[prost(message, required, tag = "1")]
    pub id: BlockID,

    /// Block format version.
    #[prost(uint32, tag = "2")]
    pub version: u32,

    /// Id of the previous block.
    #[prost(message, required, tag = "3")]
    pub parent_id: BlockID,

    /// The index of this block in the blockchain.
    #[prost(uint64, tag = "4")]
    pub index: BlockIndex,

    /// The cumulative number of Txos in the blockchain, including this block.
    #[prost(uint64, tag = "5")]
    pub cumulative_txo_count: u64,

    /// Root hash of the membership proofs provided by the untrusted local
    /// system for validation. This captures the state of all TxOuts in the
    /// ledger that this block was validated against.
    #[prost(message, required, tag = "6")]
    pub root_element: TxOutMembershipElement,

    /// Hash of the block's contents.
    #[prost(message, required, tag = "7")]
    pub contents_hash: BlockContentsHash,
}

impl Block {
    /// Creates the origin block.
    ///
    /// # Arguments
    /// * `outputs` - Outputs "minted" by the origin block.
    pub fn new_origin_block(outputs: &[TxOut]) -> Self {
        let version = 0; // The origin block is always 0
        let parent_id = BlockID::default();
        let index: BlockIndex = 0;
        let cumulative_txo_count = outputs.len() as u64;
        let root_element = TxOutMembershipElement::default();
        // The origin block does not contain any key images.
        let key_images = Vec::new();
        let block_contents = BlockContents::new(key_images, outputs.to_vec());
        let contents_hash = block_contents.hash();
        let id = compute_block_id(
            version,
            &parent_id,
            index,
            cumulative_txo_count,
            &root_element,
            &contents_hash,
        );
        Self {
            id,
            version,
            parent_id,
            index,
            cumulative_txo_count,
            root_element,
            contents_hash,
        }
    }

    /// Creates a new `Block` intermediate in the block chain, from a parent
    /// block Adds 1 to the parent.index, and adds
    /// block_contents.outputs.len() to the parent.cumulative_txo_count, to
    /// compute values for the next block.
    ///
    /// # Arguments
    /// * `version` - The block format version
    /// * `parent` - The parent block
    /// * `root_element` - The root element for membership proofs
    /// * `block_contents - The Contents of the block.
    pub fn new_with_parent(
        version: u32,
        parent: &Block,
        root_element: &TxOutMembershipElement,
        block_contents: &BlockContents,
    ) -> Self {
        Block::new(
            version,
            &parent.id,
            parent.index + 1,
            parent.cumulative_txo_count + block_contents.outputs.len() as u64,
            root_element,
            block_contents,
        )
    }

    /// Creates a new `Block`.
    /// This low-level version doesn't require having the parent block in hand,
    /// and takes all needed metadata for the block header as input.
    ///
    /// # Arguments
    /// * `version` - The block format version.
    /// * `parent_id` - `BlockID` of previous block in the blockchain.
    /// * `index` - The index of this block in the blockchain.
    /// * `cumulative_txo_count` - The cumulative txo count *including this
    ///   block*
    /// * `root_element` - The root element for membership proofs
    /// * `block_contents` - Contents of the block.
    pub fn new(
        version: u32,
        parent_id: &BlockID,
        index: BlockIndex,
        cumulative_txo_count: u64,
        root_element: &TxOutMembershipElement,
        block_contents: &BlockContents,
    ) -> Self {
        let contents_hash = block_contents.hash();
        let id = compute_block_id(
            version,
            parent_id,
            index,
            cumulative_txo_count,
            root_element,
            &contents_hash,
        );

        Self {
            id,
            version,
            parent_id: parent_id.clone(),
            index,
            cumulative_txo_count,
            root_element: root_element.clone(),
            contents_hash,
        }
    }

    /// Checks if the block's ID is valid for the block.
    /// A block constructed with `new` will be valid by virtue of `calling
    /// compute_block_id` on construction. However, when converting between
    /// different block representations, you need to validate that the contents
    /// of the converted structure is valid.
    pub fn is_block_id_valid(&self) -> bool {
        let expected_id = compute_block_id(
            self.version,
            &self.parent_id,
            self.index,
            self.cumulative_txo_count,
            &self.root_element,
            &self.contents_hash,
        );

        self.id == expected_id
    }
}

/// Computes the BlockID by hashing the contents of a block.
///
/// The identifier of a block is the result of hashing everything inside a block
/// except the `id` field.
pub fn compute_block_id(
    version: u32,
    parent_id: &BlockID,
    index: BlockIndex,
    cumulative_txo_count: u64,
    root_element: &TxOutMembershipElement,
    contents_hash: &BlockContentsHash,
) -> BlockID {
    let mut transcript = MerlinTranscript::new(b"mobilecoin-block-id");

    version.append_to_transcript(b"version", &mut transcript);
    parent_id.append_to_transcript(b"parent_id", &mut transcript);
    index.append_to_transcript(b"index", &mut transcript);
    cumulative_txo_count.append_to_transcript(b"cumulative_txo_count", &mut transcript);
    root_element.append_to_transcript(b"root_element", &mut transcript);
    contents_hash.append_to_transcript(b"contents_hash", &mut transcript);

    let mut result = [0u8; 32];
    transcript.extract_digest(&mut result);

    BlockID(result)
}

#[cfg(test)]
mod block_tests {
    use crate::{
        encrypted_fog_hint::EncryptedFogHint,
        membership_proofs::Range,
        ring_signature::KeyImage,
        tx::{TxOut, TxOutMembershipElement, TxOutMembershipHash},
        Block, BlockContents, BlockContentsHash, BlockID, BLOCK_VERSION,
    };
    use alloc::vec::Vec;
    use core::convert::TryFrom;
    use mc_account_keys::AccountKey;
    use mc_crypto_keys::RistrettoPrivate;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng};

    fn get_block_contents<RNG: CryptoRng + RngCore>(rng: &mut RNG) -> BlockContents {
        let (key_images, outputs) = get_key_images_and_outputs(rng);
        BlockContents::new(key_images, outputs)
    }

    fn get_key_images_and_outputs<RNG: CryptoRng + RngCore>(
        rng: &mut RNG,
    ) -> (Vec<KeyImage>, Vec<TxOut>) {
        let recipient = AccountKey::random(rng);

        let outputs: Vec<TxOut> = (0..8)
            .map(|_i| {
                TxOut::new(
                    rng.next_u64(),
                    &recipient.default_subaddress(),
                    &RistrettoPrivate::from_random(rng),
                    EncryptedFogHint::fake_onetime_hint(rng),
                )
                .unwrap()
            })
            .collect();

        let key_images = vec![
            KeyImage::from(rng.next_u64()),
            KeyImage::from(rng.next_u64()),
            KeyImage::from(rng.next_u64()),
        ];
        (key_images, outputs)
    }

    fn get_block<RNG: CryptoRng + RngCore>(rng: &mut RNG) -> Block {
        let bytes = [14u8; 32];
        let parent_id = BlockID::try_from(&bytes[..]).unwrap();

        let root_element = TxOutMembershipElement {
            range: Range::new(0, 15).unwrap(),
            hash: TxOutMembershipHash::from([0u8; 32]),
        };

        let block_contents = get_block_contents(rng);

        Block::new(
            BLOCK_VERSION,
            &parent_id,
            3,
            400,
            &root_element,
            &block_contents,
        )
    }

    fn get_block_with_no_memo<RNG: CryptoRng + RngCore>(rng: &mut RNG) -> Block {
        let bytes = [14u8; 32];
        let parent_id = BlockID::try_from(&bytes[..]).unwrap();

        let root_element = TxOutMembershipElement {
            range: Range::new(0, 15).unwrap(),
            hash: TxOutMembershipHash::from([0u8; 32]),
        };
        let (key_images, mut outputs) = get_key_images_and_outputs(rng);
        for ref mut output in outputs.iter_mut() {
            output.e_memo = None;
        }

        let block_contents = BlockContents::new(key_images, outputs);
        Block::new(
            BLOCK_VERSION,
            &parent_id,
            3,
            400,
            &root_element,
            &block_contents,
        )
    }

    #[test]
    /// The block returned by `get_block` should have a valid BlockID.
    fn test_get_block_has_valid_id() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let block = get_block(&mut rng);
        assert!(block.is_block_id_valid());
    }

    #[test]
    /// The block ID should depend on the block version.
    fn test_block_id_includes_version() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut block = get_block(&mut rng);
        block.version += 1;
        assert!(!block.is_block_id_valid());
    }

    #[test]
    /// The block ID should depend on the parent_id.
    fn test_block_id_includes_parent_id() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut block = get_block(&mut rng);

        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let wrong_parent_id = BlockID(bytes);

        block.parent_id = wrong_parent_id;
        assert!(!block.is_block_id_valid());
    }

    #[test]
    /// The block ID should depend on the block's index.
    fn test_block_id_includes_block_index() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut block = get_block(&mut rng);
        block.index += 1;
        assert!(!block.is_block_id_valid());
    }

    #[test]
    /// The block ID should depend on the root element.
    fn test_block_id_includes_root_element() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut block = get_block(&mut rng);

        let wrong_root_element = TxOutMembershipElement {
            range: Range::new(13, 17).unwrap(),
            hash: Default::default(),
        };
        block.root_element = wrong_root_element;
        assert!(!block.is_block_id_valid());
    }

    #[test]
    /// The block ID should depend on the content_hash.
    fn test_block_id_includes_content_hash() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut block = get_block(&mut rng);

        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let wrong_content_hash = BlockContentsHash(bytes);

        block.contents_hash = wrong_content_hash;
        assert!(!block.is_block_id_valid());
    }

    #[test]
    #[ignore]
    // TODO: Block::new should return an error if `tx_hashes` contains duplicates.
    fn test_block_errors_on_duplicate_tx_hashes() {
        unimplemented!()
    }

    #[test]
    /// The block ID and block contents hash do not change as the code evolves.
    /// This test was written by writing a failed assert and then copying the
    /// actual block id into the test. This should hopefully catches cases where
    /// we add/change Block/BlockContents and accidentally break id
    /// calculation of old blocks.
    fn test_hashing_is_consistent() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        //Check hash with memo
        let block = get_block(&mut rng);
        assert_eq!(
            block.id.as_ref(),
            &[
                118, 205, 187, 34, 207, 104, 52, 137, 97, 124, 79, 205, 112, 204, 146, 217, 128,
                178, 169, 214, 231, 120, 46, 237, 17, 93, 59, 136, 101, 131, 197, 217
            ]
        );

        let block_contents = get_block_contents(&mut rng);
        assert_eq!(
            block_contents.hash().as_ref(),
            &[
                130, 252, 161, 182, 34, 248, 219, 175, 99, 76, 204, 54, 204, 35, 147, 41, 168, 222,
                68, 11, 76, 106, 243, 173, 136, 27, 208, 27, 85, 199, 193, 241
            ]
        );

        //Check hash without memo
        let block_with_no_memo = get_block_with_no_memo(&mut rng);
        assert_eq!(
            block_with_no_memo.id.as_ref(),
            &[
                243, 102, 219, 76, 169, 151, 159, 65, 84, 34, 178, 32, 207, 95, 133, 127, 68, 161,
                140, 254, 120, 243, 90, 232, 156, 40, 132, 101, 203, 160, 12, 159
            ]
        );

        assert_eq!(
            block_with_no_memo.contents_hash.as_ref(),
            &[
                69, 203, 184, 52, 204, 228, 5, 91, 161, 228, 220, 116, 182, 23, 169, 32, 76, 104,
                121, 186, 195, 20, 142, 138, 69, 155, 193, 215, 226, 117, 134, 74
            ]
        );
    }
}
