// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::{Error, Ledger};
use common::{HashMap, HashSet};
use curve25519_dalek::ristretto::RistrettoPoint;
use keys::{FromRandom, RistrettoPrivate};
use rand::{rngs::StdRng, SeedableRng};
use std::{
    iter::FromIterator,
    sync::{Arc, Mutex, MutexGuard},
};
use transaction::{
    account_keys::AccountKey,
    ring_signature::KeyImage,
    tx::{TxHash, TxOut, TxOutMembershipElement, TxOutMembershipProof},
    Block, BlockID, BlockSignature, RedactedTx, BLOCK_VERSION,
};

pub struct MockLedgerInner {
    pub blocks_by_block_number: HashMap<u64, Block>,
    pub blocks_by_block_id: HashMap<BlockID, Block>,
    pub transactions_by_block_number: HashMap<u64, Vec<RedactedTx>>,
    pub transactions_by_hash: HashMap<TxHash, RedactedTx>,
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
            inner: Arc::new(Mutex::new(MockLedgerInner {
                blocks_by_block_number: HashMap::default(),
                blocks_by_block_id: HashMap::default(),
                transactions_by_block_number: HashMap::default(),
                transactions_by_hash: HashMap::default(),
                tx_outs: HashSet::default(),
                membership_proofs: HashMap::default(),
                key_images_by_block_number: HashMap::default(),
                key_images: HashMap::default(),
            })),
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
    /// * `transactions` - Transactions referenced by hashes in the `block`.
    pub fn set_block(&mut self, block: &Block, transactions: &[RedactedTx]) {
        let mut inner = self.lock();

        inner
            .blocks_by_block_number
            .insert(block.index, block.clone());
        inner
            .blocks_by_block_id
            .insert(block.id.clone(), block.clone());
        inner
            .transactions_by_block_number
            .insert(block.index, transactions.to_vec());
        for tx_stored in transactions {
            let hash = tx_stored.hash();
            inner.transactions_by_hash.insert(hash, tx_stored.clone());
        }
        for tx_stored in transactions {
            for tx_out in &tx_stored.outputs {
                inner.tx_outs.insert(tx_out.clone());
            }
        }

        let key_images: Vec<KeyImage> = transactions
            .iter()
            .flat_map(|redacted_tx| redacted_tx.key_images.clone())
            .collect();
        inner.key_images = HashMap::from_iter(key_images.iter().map(|ki| (*ki, block.index)));
        inner
            .key_images_by_block_number
            .insert(block.index, key_images);
    }
}

impl Ledger for MockLedger {
    fn append_block(
        &mut self,
        block: &Block,
        transactions: &[RedactedTx],
        _signature: Option<&BlockSignature>,
    ) -> Result<(), Error> {
        assert_eq!(block.index, self.num_blocks().unwrap());
        self.set_block(block, transactions);
        Ok(())
    }

    fn num_blocks(&self) -> Result<u64, Error> {
        Ok(self.lock().blocks_by_block_number.len() as u64)
    }

    fn num_txs(&self) -> Result<u64, Error> {
        Ok(self.lock().transactions_by_hash.len() as u64)
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

    fn get_block_signature(&self, _block_number: u64) -> Result<BlockSignature, Error> {
        Err(Error::NotFound)
    }

    fn get_tx_out_index_by_hash(&self, _tx_out_hash: &[u8; 32]) -> Result<u64, Error> {
        // Unused for these tests.
        unimplemented!()
    }

    fn get_tx_out_by_index(&self, _: u64) -> Result<TxOut, Error> {
        // Unused for these tests.
        unimplemented!()
    }

    fn get_transactions_by_block(&self, block_number: u64) -> Result<Vec<RedactedTx>, Error> {
        self.lock()
            .transactions_by_block_number
            .get(&block_number)
            .cloned()
            .ok_or(Error::NotFound)
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
}

#[allow(dead_code)]
/// Creates a MockLedger and populates it with blocks and transactions.
pub fn get_mock_ledger(n_blocks: usize) -> MockLedger {
    let mut mock_ledger = MockLedger::default();
    let blocks_and_transactions = get_test_ledger_blocks(n_blocks);
    for (block, transactions) in blocks_and_transactions {
        mock_ledger.set_block(&block, &transactions);
    }
    mock_ledger
}

#[allow(dead_code)]
/// Creates a sequence of `Block`s and the transactions corresponding to each block.
pub fn get_test_ledger_blocks(n_blocks: usize) -> Vec<(Block, Vec<RedactedTx>)> {
    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

    // The owner of all outputs in the mock ledger.
    let account_key = AccountKey::random(&mut rng);

    let value = 134_217_728; // 2^27
                             // let zero_key = RistrettoPublic::try_from(&[0u8; 32]).unwrap();

    let mut block_ids: Vec<BlockID> = Vec::with_capacity(n_blocks);
    let mut blocks_and_transactions: Vec<(Block, Vec<RedactedTx>)> = Vec::with_capacity(n_blocks);

    for block_index in 0..n_blocks {
        if block_index == 0 {
            // Create the origin block.

            let tx_out = TxOut::new(
                value,
                &account_key.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
                &mut rng,
            )
            .unwrap();

            let redacted_tx = RedactedTx::new(vec![tx_out], vec![]);
            let redacted_transactions = vec![redacted_tx];
            let origin_block = Block::new_origin_block(&redacted_transactions);
            block_ids.push(origin_block.id.clone());
            blocks_and_transactions.push((origin_block, redacted_transactions));
        } else {
            // Create a normal block.
            let parent_id: BlockID = block_ids[block_index - 1].clone();

            let tx_out = TxOut::new(
                16,
                &account_key.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
                &mut rng,
            )
            .unwrap();

            let redacted_tx = RedactedTx {
                outputs: vec![tx_out],
                key_images: vec![KeyImage::from(RistrettoPoint::random(&mut rng))],
            };

            let redacted_transactions = vec![redacted_tx];
            // Compute cumulative_txo_count
            let cumulative_txo_count = blocks_and_transactions[block_index - 1]
                .0
                .cumulative_txo_count
                + redacted_transactions.len() as u64;
            let block = Block::new(
                BLOCK_VERSION,
                &parent_id,
                block_index as u64,
                cumulative_txo_count,
                &TxOutMembershipElement::default(),
                &redacted_transactions,
            );
            block_ids.push(block.id.clone());
            blocks_and_transactions.push((block, redacted_transactions));
        }
    }

    blocks_and_transactions
}

#[cfg(test)]
mod tests {
    use super::*;
    use transaction::{compute_block_id, hash_block_contents};

    #[test]
    // `get_test_ledger_blocks` should return a valid blockchain of the specified length.
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
        for (block, transactions) in blocks_and_transactions {
            assert_eq!(block.contents_hash, hash_block_contents(&transactions));
        }
    }
}
