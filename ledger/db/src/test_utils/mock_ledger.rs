// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{ActiveMintConfig, ActiveMintConfigs, Error, Ledger};
use mc_account_keys::AccountKey;
use mc_blockchain_types::{
    Block, BlockContents, BlockData, BlockID, BlockIndex, BlockMetadata, BlockSignature,
    BlockVersion,
};
use mc_common::{HashMap, HashSet};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate};
use mc_transaction_core::{
    constants::TOTAL_MOB,
    mint::MintTx,
    ring_signature::KeyImage,
    tokens::Mob,
    tx::{TxOut, TxOutMembershipElement, TxOutMembershipProof},
    Amount, Token, TokenId,
};
use mc_util_from_random::FromRandom;
use rand::{rngs::StdRng, SeedableRng};
use rand_core::RngCore;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Default)]
pub struct MockLedgerInner {
    pub blocks_by_block_number: HashMap<u64, Block>,
    pub blocks_by_block_id: HashMap<BlockID, Block>,
    pub block_contents_by_block_number: HashMap<u64, BlockContents>,
    pub block_number_by_tx_out_index: HashMap<u64, u64>,
    pub tx_outs: HashSet<TxOut>,
    pub membership_proofs: HashMap<u64, TxOutMembershipProof>,
    pub key_images_by_block_number: HashMap<u64, Vec<KeyImage>>,
    pub key_images: HashMap<KeyImage, u64>,
}

#[derive(Clone)]
pub struct MockLedger {
    inner: Arc<Mutex<MockLedgerInner>>,
}

impl Default for MockLedger {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockLedgerInner::default())),
        }
    }
}

impl MockLedger {
    pub fn lock(&self) -> MutexGuard<MockLedgerInner> {
        self.inner.lock().expect("mutex poisoned")
    }

    /// Writes a given index of the blockchain.
    ///
    /// # Arguments
    /// * `block` - Block to write.
    /// * `block_contents` - Contents of the block.
    pub fn set_block(&mut self, block: &Block, block_contents: &BlockContents) {
        let mut inner = self.lock();

        inner
            .blocks_by_block_number
            .insert(block.index, block.clone());
        inner
            .blocks_by_block_id
            .insert(block.id.clone(), block.clone());

        inner
            .block_contents_by_block_number
            .insert(block.index, block_contents.clone());

        for tx_out in &block_contents.outputs {
            let tx_out_index = inner.tx_outs.len() as u64;
            inner.tx_outs.insert(tx_out.clone());
            inner
                .block_number_by_tx_out_index
                .insert(tx_out_index, block.index);
        }

        let key_images = block_contents.key_images.clone();
        inner.key_images = key_images.iter().map(|ki| (*ki, block.index)).collect();

        inner
            .key_images_by_block_number
            .insert(block.index, key_images);
    }
}

impl Ledger for MockLedger {
    fn append_block<'b>(
        &mut self,
        block: &'b Block,
        block_contents: &'b BlockContents,
        _signature: Option<&'b BlockSignature>,
        _metadata: Option<&'b BlockMetadata>,
    ) -> Result<(), Error> {
        assert_eq!(block.index, self.num_blocks().unwrap());
        self.set_block(block, block_contents);
        Ok(())
    }

    fn num_blocks(&self) -> Result<u64, Error> {
        Ok(self.lock().blocks_by_block_number.len() as u64)
    }

    fn num_txos(&self) -> Result<u64, Error> {
        Ok(self.lock().tx_outs.len() as u64)
    }

    fn get_block(&self, block_number: u64) -> Result<Block, Error> {
        self.lock()
            .blocks_by_block_number
            .get(&block_number)
            .cloned()
            .ok_or(Error::NotFound)
    }

    fn get_block_contents(&self, block_number: u64) -> Result<BlockContents, Error> {
        self.lock()
            .block_contents_by_block_number
            .get(&block_number)
            .cloned()
            .ok_or(Error::NotFound)
    }

    fn get_block_signature(&self, _block_number: u64) -> Result<BlockSignature, Error> {
        Err(Error::NotFound)
    }

    fn get_block_metadata(&self, _block_number: u64) -> Result<BlockMetadata, Error> {
        Err(Error::NotFound)
    }

    fn get_block_data(&self, block_number: u64) -> Result<BlockData, Error> {
        let block = self.get_block(block_number)?;
        let contents = self.get_block_contents(block_number)?;
        let signature = self.get_block_signature(block_number).ok();
        let metadata = self.get_block_metadata(block_number).ok();
        Ok(BlockData::new(block, contents, signature, metadata))
    }

    /// Gets block index by a TxOut global index.
    fn get_block_index_by_tx_out_index(&self, tx_out_index: u64) -> Result<u64, Error> {
        self.lock()
            .block_number_by_tx_out_index
            .get(&tx_out_index)
            .cloned()
            .ok_or(Error::NotFound)
    }

    fn get_tx_out_index_by_hash(&self, _tx_out_hash: &[u8; 32]) -> Result<u64, Error> {
        // Unused for these tests.
        unimplemented!()
    }

    fn get_tx_out_by_index(&self, _: u64) -> Result<TxOut, Error> {
        // Unused for these tests.
        unimplemented!()
    }

    fn get_tx_out_index_by_public_key(
        &self,
        _tx_out_public_key: &CompressedRistrettoPublic,
    ) -> Result<u64, Error> {
        unimplemented!();
    }

    fn contains_tx_out_public_key(
        &self,
        _public_key: &CompressedRistrettoPublic,
    ) -> Result<bool, Error> {
        unimplemented!();
    }

    fn check_key_image(&self, key_image: &KeyImage) -> Result<Option<u64>, Error> {
        // Unused for these tests.
        Ok(self.lock().key_images.get(key_image).cloned())
    }

    fn get_key_images_by_block(&self, _block_number: u64) -> Result<Vec<KeyImage>, Error> {
        // Unused for these tests.
        unimplemented!()
    }

    fn get_tx_out_proof_of_memberships(
        &self,
        indexes: &[u64],
    ) -> Result<Vec<TxOutMembershipProof>, Error> {
        let inner = self.lock();
        indexes
            .iter()
            .map(|index| {
                inner
                    .membership_proofs
                    .get(index)
                    .cloned()
                    .ok_or(Error::NotFound)
            })
            .collect()
    }

    fn get_root_tx_out_membership_element(&self) -> Result<TxOutMembershipElement, Error> {
        unimplemented!();
    }

    fn get_active_mint_configs(
        &self,
        _token_id: TokenId,
    ) -> Result<Option<ActiveMintConfigs>, Error> {
        unimplemented!()
    }

    fn get_active_mint_configs_map(&self) -> Result<HashMap<TokenId, ActiveMintConfigs>, Error> {
        unimplemented!()
    }

    fn check_mint_config_tx_nonce(&self, _nonce: &[u8]) -> Result<Option<BlockIndex>, Error> {
        unimplemented!()
    }

    fn check_mint_tx_nonce(&self, _nonce: &[u8]) -> Result<Option<BlockIndex>, Error> {
        unimplemented!()
    }

    fn get_active_mint_config_for_mint_tx(
        &self,
        _mint_tx: &MintTx,
    ) -> Result<ActiveMintConfig, Error> {
        unimplemented!()
    }
}

/// Creates a MockLedger and populates it with blocks and transactions.
pub fn get_mock_ledger(n_blocks: usize) -> MockLedger {
    let mut mock_ledger = MockLedger::default();
    let blocks_and_transactions = get_test_ledger_blocks(n_blocks);
    for (block, block_contents) in blocks_and_transactions {
        mock_ledger.set_block(&block, &block_contents);
    }
    mock_ledger
}

/// Creates a sequence of `Block`s and the transactions corresponding to each
/// block.
pub fn get_test_ledger_blocks(n_blocks: usize) -> Vec<(Block, BlockContents)> {
    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

    // The owner of all outputs in the mock ledger.
    let account_key = AccountKey::random(&mut rng);
    let value = 134_217_728; // 2^27
    let token_id = Mob::ID;

    let mut block_ids: Vec<BlockID> = Vec::with_capacity(n_blocks);
    let mut blocks_and_contents: Vec<(Block, BlockContents)> = Vec::with_capacity(n_blocks);

    for block_index in 0..n_blocks {
        if block_index == 0 {
            // Create the origin block.
            let mut tx_out = TxOut::new(
                BlockVersion::ZERO,
                Amount { value, token_id },
                &account_key.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
            )
            .unwrap();
            // Version 0 tx_out in the origin block don't have memos
            tx_out.e_memo = None;

            let outputs = vec![tx_out];
            let origin_block = Block::new_origin_block(&outputs);
            let block_contents = BlockContents {
                outputs,
                ..Default::default()
            };
            block_ids.push(origin_block.id.clone());
            blocks_and_contents.push((origin_block, block_contents));
        } else {
            // Create a normal block.
            let tx_out = TxOut::new(
                BlockVersion::MAX,
                Amount {
                    value: 16,
                    token_id,
                },
                &account_key.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
            )
            .unwrap();

            let outputs = vec![tx_out];
            let key_images = vec![KeyImage::from(rng.next_u64())];
            let block_contents = BlockContents {
                key_images,
                outputs,
                ..Default::default()
            };

            let block = Block::new_with_parent(
                BlockVersion::ZERO,
                &blocks_and_contents[block_index - 1].0,
                &TxOutMembershipElement::default(),
                &block_contents,
            );
            block_ids.push(block.id.clone());
            blocks_and_contents.push((block, block_contents));
        }
    }

    blocks_and_contents
}

/// Get blocks with custom content in order to simulate conditions seen in
/// production
///
/// * `outputs_per_recipient_per_token_per_block` - number of outputs for each
///   unique token type per account per block
/// * `num_accounts` - number of accounts in the blocks
/// * `num_blocks` - number of simulated blocks to create
/// * `key_images_per_block` - number of key images per block
/// * `max_token_id` - number of distinct token ids in blocks
pub fn get_custom_test_ledger_blocks(
    outputs_per_recipient_per_token_per_block: usize,
    num_accounts: usize,
    num_blocks: usize,
    key_images_per_block: usize,
    max_token_id: u64,
) -> Vec<(Block, BlockContents)> {
    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

    // Number of total tx outputs in all blocks
    let num_outputs: u64 = (num_accounts
        * outputs_per_recipient_per_token_per_block
        * num_blocks
        * (max_token_id as usize + 1)) as u64;
    assert!(num_outputs >= 16);

    // Initialize other defaults
    let picomob_per_output: u64 =
        ((TOTAL_MOB as f64 / num_outputs as f64) * 1000000000000.0) as u64;
    let recipients = (0..num_accounts)
        .map(|_| AccountKey::random(&mut rng).default_subaddress())
        .collect::<Vec<_>>();
    let block_version = BlockVersion::MAX;
    let mut blocks_and_contents: Vec<(Block, BlockContents)> = Vec::new();
    let mut previous_block: Option<Block> = None;

    // Create the tx outs for all of the simulated blocks
    for _ in 0..num_blocks {
        let mut outputs: Vec<TxOut> = Vec::new();
        for recipient in &recipients {
            let tx_private_key = RistrettoPrivate::from_random(&mut rng);
            for _ in 0..outputs_per_recipient_per_token_per_block {
                // Create outputs for each token id
                for token_id in 0..=max_token_id {
                    let amount = Amount {
                        value: picomob_per_output,
                        token_id: token_id.into(),
                    };
                    let output = TxOut::new(
                        BlockVersion::MAX,
                        amount,
                        recipient,
                        &tx_private_key,
                        Default::default(),
                    );
                    outputs.push(output.unwrap());
                }
            }
        }

        // Create key images unless we're at the origin block
        let key_images: Vec<KeyImage> = if previous_block.is_some() {
            (0..key_images_per_block)
                .map(|_i| KeyImage::from(rng.next_u64()))
                .collect()
        } else {
            Default::default()
        };

        let block_contents = BlockContents {
            key_images,
            outputs: outputs.clone(),
            ..Default::default()
        };

        // Create a block with the desired contents
        let block = match previous_block {
            Some(parent) => {
                Block::new_with_parent(block_version, &parent, &Default::default(), &block_contents)
            }
            None => Block::new_origin_block(&outputs),
        };

        previous_block = Some(block.clone());
        blocks_and_contents.push((block, block_contents));
    }
    blocks_and_contents
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_blockchain_types::compute_block_id;

    #[test]
    // `get_custom_test_ledger_blocks` should return blocks that match the
    // configuration specified in the arguments and pass all normal
    // consistency tests
    fn test_custom_block_correctness() {
        let blocks_and_transactions = get_custom_test_ledger_blocks(2, 3, 3, 3, 0);

        let blocks: Vec<Block> = blocks_and_transactions
            .iter()
            .map(|(block, _transactions)| block.clone())
            .collect();

        // Ensure the correct amount of blocks have been created
        assert_eq!(blocks_and_transactions.len(), 3);

        // Ensure the origin block id isn't a hash of another block
        let origin_block: &Block = blocks.get(0).unwrap();
        assert_eq!(origin_block.parent_id.as_ref(), [0u8; 32]);
        assert_eq!(origin_block.index, 0);

        for (block, block_contents) in blocks_and_transactions.iter() {
            let derived_block_id = compute_block_id(
                block.version,
                &block.parent_id,
                block.index,
                block.cumulative_txo_count,
                &block.root_element,
                &block.contents_hash,
            );

            // Ensure the block_id matches the id computed via the merlin transcript
            assert_eq!(derived_block_id, block.id);

            // Ensure stated block hash matches the computed hash
            assert_eq!(block.contents_hash, block_contents.hash());

            // Ensure the amount of transactions present matches expected amount
            assert_eq!(block.cumulative_txo_count, (block.index + 1) * 6);

            // Ensure the correct number of key images exist
            if block.index == 0 {
                assert_eq!(block_contents.key_images.len(), 0);
            } else {
                assert_eq!(block_contents.key_images.len(), 3);
            }
        }
    }

    #[test]
    // `get_test_ledger_blocks` should return a valid blockchain of the specified
    // length.
    fn test_get_test_ledger_blocks() {
        let blocks_and_transactions = get_test_ledger_blocks(3);
        assert_eq!(
            blocks_and_transactions.len(),
            3,
            "{:#?}",
            blocks_and_transactions
        );

        let blocks: Vec<Block> = blocks_and_transactions
            .iter()
            .map(|(block, _transactions)| block.clone())
            .collect();

        // The first block must be the origin block.
        let origin_block: &Block = blocks.get(0).unwrap();
        assert_eq!(origin_block.parent_id.as_ref(), [0u8; 32]);
        assert_eq!(origin_block.index, 0);

        // Each block's parent_id must be the block_id of the previous block.
        let mut previous_block = origin_block;
        for block in blocks[1..].iter() {
            assert_eq!(block.parent_id, previous_block.id);
            previous_block = block;
        }

        // Each block's ID must agree with the block content hashes.
        for (block, _transactions) in blocks_and_transactions.iter() {
            let derived_block_id = compute_block_id(
                block.version,
                &block.parent_id,
                block.index,
                block.cumulative_txo_count,
                &block.root_element,
                &block.contents_hash,
            );
            assert_eq!(block.id, derived_block_id);
        }

        // Contents hashes maust match contents
        for (block, block_contents) in blocks_and_transactions {
            assert_eq!(block.contents_hash, block_contents.hash());
        }
    }
}
