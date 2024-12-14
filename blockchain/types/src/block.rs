// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{BlockContents, BlockContentsHash, BlockID, BlockVersion};
use mc_crypto_digestible::{DigestTranscript, Digestible, MerlinTranscript};
use mc_transaction_core::tx::{TxOut, TxOutMembershipElement};
use prost::Message;
use serde::{Deserialize, Serialize};

/// The maximum supported block format version for this build of
/// mc-transaction-core
pub const MAX_BLOCK_VERSION: BlockVersion = BlockVersion::MAX;

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

    /// Timestamp of the block. ms since Unix epoch
    #[prost(uint64, tag = "8")]
    #[digestible(omit_when = 0)]
    pub timestamp: u64,
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
        let timestamp = 0;

        // The origin block does not contain anything but TxOuts.
        let block_contents = BlockContents {
            outputs: outputs.to_vec(),
            ..Default::default()
        };

        let contents_hash = block_contents.hash();
        let id = compute_block_id(
            version,
            &parent_id,
            index,
            cumulative_txo_count,
            &root_element,
            &contents_hash,
            timestamp,
        );
        Self {
            id,
            version,
            parent_id,
            index,
            cumulative_txo_count,
            root_element,
            contents_hash,
            timestamp,
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
    /// * `block_contents` - The Contents of the block.
    /// * `timestamp` - The timestamp of the block in ms since Unix epoch.
    ///   should be 0 for block versions 3 and below.
    pub fn new_with_parent(
        version: BlockVersion,
        parent: &Block,
        root_element: &TxOutMembershipElement,
        block_contents: &BlockContents,
        timestamp: u64,
    ) -> Self {
        Block::new(
            version,
            &parent.id,
            parent.index + 1,
            parent.cumulative_txo_count + block_contents.outputs.len() as u64,
            root_element,
            block_contents,
            timestamp,
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
    /// * `timestamp` - The timestamp of the block in ms since Unix epoch.
    ///   should be 0 for block versions 3 and below, and set for block versions
    ///   4 and above.
    pub fn new(
        version: BlockVersion,
        parent_id: &BlockID,
        index: BlockIndex,
        cumulative_txo_count: u64,
        root_element: &TxOutMembershipElement,
        block_contents: &BlockContents,
        timestamp: u64,
    ) -> Self {
        let contents_hash = block_contents.hash();
        let id = compute_block_id(
            *version,
            parent_id,
            index,
            cumulative_txo_count,
            root_element,
            &contents_hash,
            timestamp,
        );

        Self {
            id,
            version: *version,
            parent_id: parent_id.clone(),
            index,
            cumulative_txo_count,
            root_element: root_element.clone(),
            contents_hash,
            timestamp,
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
            self.timestamp,
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
    timestamp: u64,
) -> BlockID {
    let mut transcript = MerlinTranscript::new(b"mobilecoin-block-id");

    version.append_to_transcript(b"version", &mut transcript);
    parent_id.append_to_transcript(b"parent_id", &mut transcript);
    index.append_to_transcript(b"index", &mut transcript);
    cumulative_txo_count.append_to_transcript(b"cumulative_txo_count", &mut transcript);
    root_element.append_to_transcript(b"root_element", &mut transcript);
    contents_hash.append_to_transcript(b"contents_hash", &mut transcript);

    let timestamps_supported =
        BlockVersion::try_from(version).map(|v| v.timestamps_are_supported());
    if timestamps_supported.unwrap_or_default() {
        timestamp.append_to_transcript(b"timestamp", &mut transcript);
    }

    let mut result = [0u8; 32];
    transcript.extract_digest(&mut result);

    BlockID(result)
}

#[cfg(test)]
mod block_tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use mc_account_keys::AccountKey;
    use mc_crypto_keys::RistrettoPrivate;
    use mc_transaction_core::{
        encrypted_fog_hint::EncryptedFogHint, membership_proofs::Range, ring_signature::KeyImage,
        tokens::Mob, tx::TxOutMembershipHash, Amount, Token,
    };
    use mc_util_from_random::FromRandom;
    use mc_util_test_helper::{get_seeded_rng, CryptoRng, RngCore};

    // This is block version 1 to avoid messing with test vectors
    const BLOCK_VERSION: BlockVersion = BlockVersion::ONE;

    fn get_block_contents<RNG: CryptoRng + RngCore>(rng: &mut RNG) -> BlockContents {
        let (key_images, outputs) = get_key_images_and_outputs(rng);
        BlockContents {
            key_images,
            outputs,
            ..Default::default()
        }
    }

    fn get_key_images_and_outputs<RNG: CryptoRng + RngCore>(
        rng: &mut RNG,
    ) -> (Vec<KeyImage>, Vec<TxOut>) {
        let recipient = AccountKey::random(rng);

        let outputs: Vec<TxOut> = (0..8)
            .map(|_i| {
                TxOut::new(
                    BLOCK_VERSION,
                    Amount {
                        value: rng.next_u64(),
                        token_id: Mob::ID,
                    },
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

    fn get_block_version_1<RNG: CryptoRng + RngCore>(rng: &mut RNG) -> Block {
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
            0, // timestamp of 0 for earlier block versions
        )
    }

    fn get_block_version_4<RNG: CryptoRng + RngCore>(rng: &mut RNG) -> Block {
        let bytes = [14u8; 32];
        let parent_id = BlockID::try_from(&bytes[..]).unwrap();

        let root_element = TxOutMembershipElement {
            range: Range::new(0, 15).unwrap(),
            hash: TxOutMembershipHash::from([0u8; 32]),
        };

        let block_contents = get_block_contents(rng);

        Block::new(
            BlockVersion::FOUR,
            &parent_id,
            3,
            400,
            &root_element,
            &block_contents,
            10,
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

        let block_contents = BlockContents {
            key_images,
            outputs,
            ..Default::default()
        };
        Block::new(
            BLOCK_VERSION,
            &parent_id,
            3,
            400,
            &root_element,
            &block_contents,
            0,
        )
    }

    #[test]
    /// The block returned by `get_block` should have a valid BlockID.
    fn test_get_block_has_valid_id() {
        let mut rng = get_seeded_rng();
        let block = get_block_version_1(&mut rng);
        assert!(block.is_block_id_valid());
    }

    #[test]
    /// The block ID should depend on the block version.
    fn test_block_id_includes_version() {
        let mut rng = get_seeded_rng();
        let mut block = get_block_version_1(&mut rng);
        block.version += 1;
        assert!(!block.is_block_id_valid());
    }

    #[test]
    /// The block ID should depend on the parent_id.
    fn test_block_id_includes_parent_id() {
        let mut rng = get_seeded_rng();
        let mut block = get_block_version_1(&mut rng);

        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let wrong_parent_id = BlockID(bytes);

        block.parent_id = wrong_parent_id;
        assert!(!block.is_block_id_valid());
    }

    #[test]
    /// The block ID should depend on the block's index.
    fn test_block_id_includes_block_index() {
        let mut rng = get_seeded_rng();
        let mut block = get_block_version_1(&mut rng);
        block.index += 1;
        assert!(!block.is_block_id_valid());
    }

    #[test]
    /// The block ID should depend on the root element.
    fn test_block_id_includes_root_element() {
        let mut rng = get_seeded_rng();
        let mut block = get_block_version_1(&mut rng);

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
        let mut rng = get_seeded_rng();
        let mut block = get_block_version_1(&mut rng);

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
    fn test_hashing_is_consistent_block_version_one() {
        let mut rng = get_seeded_rng();

        //Check hash with memo
        let block = get_block_version_1(&mut rng);
        assert_eq!(
            block.id.as_ref(),
            &[
                222, 73, 210, 166, 125, 94, 48, 79, 128, 55, 120, 50, 68, 204, 131, 52, 79, 71, 91,
                196, 93, 86, 209, 152, 155, 234, 26, 192, 162, 165, 160, 20
            ]
        );

        let block_contents = get_block_contents(&mut rng);
        assert_eq!(
            block_contents.hash().as_ref(),
            &[
                46, 242, 28, 218, 210, 76, 187, 220, 72, 72, 53, 58, 24, 41, 6, 239, 131, 81, 192,
                252, 93, 136, 35, 91, 185, 32, 94, 1, 156, 71, 94, 14
            ]
        );

        //Check hash without memo
        let block_with_no_memo = get_block_with_no_memo(&mut rng);
        assert_eq!(
            block_with_no_memo.id.as_ref(),
            &[
                191, 207, 107, 78, 75, 166, 31, 130, 48, 139, 206, 247, 211, 79, 37, 153, 169, 188,
                212, 128, 226, 182, 22, 223, 6, 163, 168, 123, 127, 114, 70, 138
            ]
        );

        assert_eq!(
            block_with_no_memo.contents_hash.as_ref(),
            &[
                243, 164, 40, 173, 7, 115, 68, 93, 208, 45, 219, 161, 198, 90, 201, 188, 104, 67,
                1, 213, 3, 151, 104, 78, 72, 109, 223, 131, 19, 119, 118, 95
            ]
        );
    }
    #[test]
    /// The block ID hash do not change as the code evolves.
    /// This test was written by writing a failed assert and then copying the
    /// actual block id into the test. This should hopefully catches cases where
    /// we add/change Block/BlockContents and accidentally break id
    /// calculation of old blocks.
    fn test_hashing_is_consistent_block_version_four() {
        let mut rng = get_seeded_rng();

        let block = get_block_version_4(&mut rng);
        assert_eq!(
            block.id.as_ref(),
            &[
                156, 155, 244, 98, 84, 234, 204, 146, 224, 142, 236, 197, 11, 69, 5, 74, 109, 160,
                123, 173, 206, 100, 224, 171, 72, 35, 208, 137, 150, 168, 43, 93
            ]
        );
    }

    #[test]
    fn test_block_version_3_ignores_timestamp_in_id() {
        let parent_id = BlockID::try_from(&[1u8; 32][..]).unwrap();
        let index = 1;
        let cumulative_txo_count = 1;
        let root_element = TxOutMembershipElement::default();
        let contents_hash = BlockContentsHash::default();
        let timestamp_1 = 1;
        let id_1 = compute_block_id(
            3,
            &parent_id,
            index,
            cumulative_txo_count,
            &root_element,
            &contents_hash,
            timestamp_1,
        );
        let timestamp_2 = 2;
        let id_2 = compute_block_id(
            3,
            &parent_id,
            index,
            cumulative_txo_count,
            &root_element,
            &contents_hash,
            timestamp_2,
        );
        assert_eq!(id_1, id_2);
    }

    #[test]
    fn test_block_version_4_takes_timestamp_into_account() {
        let parent_id = BlockID::try_from(&[1u8; 32][..]).unwrap();
        let index = 1;
        let cumulative_txo_count = 1;
        let root_element = TxOutMembershipElement::default();
        let contents_hash = BlockContentsHash::default();
        let timestamp_1 = 1;
        let id_1 = compute_block_id(
            4,
            &parent_id,
            index,
            cumulative_txo_count,
            &root_element,
            &contents_hash,
            timestamp_1,
        );
        let timestamp_2 = 2;
        let id_2 = compute_block_id(
            4,
            &parent_id,
            index,
            cumulative_txo_count,
            &root_element,
            &contents_hash,
            timestamp_2,
        );
        assert_ne!(id_1, id_2);
    }
}
