// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{ActiveMintConfig, ActiveMintConfigs, Error, Ledger};
use mc_blockchain_test_utils::get_blocks;
use mc_blockchain_types::{
    Block, BlockContents, BlockData, BlockID, BlockIndex, BlockMetadata, BlockSignature,
    BlockVersion,
};
use mc_common::{HashMap, HashSet};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_transaction_core::{
    mint::MintTx,
    ring_signature::KeyImage,
    tx::{TxOut, TxOutMembershipElement, TxOutMembershipProof},
    TokenId,
};
use mc_util_test_helper::get_seeded_rng;
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
    for block_data in get_test_ledger_blocks(n_blocks) {
        mock_ledger
            .append_block_data(&block_data)
            .expect("failed to initialize MockLedger");
    }
    mock_ledger
}

/// Creates a sequence of [BlockData] for testing.
pub fn get_test_ledger_blocks(num_blocks: usize) -> Vec<BlockData> {
    get_blocks(
        BlockVersion::ZERO,
        num_blocks,
        2,
        1,
        1,
        1 << 20,
        None,
        &mut get_seeded_rng(),
    )
}
