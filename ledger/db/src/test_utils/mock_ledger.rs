// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{ActiveMintConfig, ActiveMintConfigs, Error, Ledger};
use mc_blockchain_test_utils::get_blocks;
use mc_blockchain_types::{
    Block, BlockContents, BlockData, BlockIndex, BlockMetadata, BlockSignature, BlockVersion,
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
    pub block_data_by_index: HashMap<BlockIndex, BlockData>,
    pub block_index_by_tx_out_index: HashMap<u64, BlockIndex>,
    pub tx_outs: HashSet<TxOut>,
    pub tx_outs_by_index: HashMap<u64, TxOut>,
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
    /// * `block_data` - Block data to write.
    pub fn set_block_data(&mut self, block_data: BlockData) {
        let mut inner = self.lock();
        let block = block_data.block();
        let contents = block_data.contents();

        for tx_out in &contents.outputs {
            let tx_out_index = inner.tx_outs.len() as u64;
            assert!(
                inner.tx_outs.insert(tx_out.clone()),
                "duplicate TxOut: {:?}",
                &tx_out
            );
            inner.tx_outs_by_index.insert(tx_out_index, tx_out.clone());
            inner
                .block_index_by_tx_out_index
                .insert(tx_out_index, block.index);
        }

        for ki in &contents.key_images {
            assert!(
                inner.key_images.insert(*ki, block.index).is_none(),
                "duplicate key image: {:?}",
                ki
            );
        }

        inner.block_data_by_index.insert(block.index, block_data);
    }
}

impl Ledger for MockLedger {
    fn append_block<'b>(
        &mut self,
        block: &'b Block,
        block_contents: &'b BlockContents,
        signature: Option<&'b BlockSignature>,
        metadata: Option<&'b BlockMetadata>,
    ) -> Result<(), Error> {
        assert_eq!(block.index, self.num_blocks().unwrap());
        self.set_block_data(BlockData::new(
            block.clone(),
            block_contents.clone(),
            signature.cloned(),
            metadata.cloned(),
        ));
        Ok(())
    }

    fn num_blocks(&self) -> Result<u64, Error> {
        Ok(self.lock().block_data_by_index.len() as u64)
    }

    fn get_block(&self, block_index: BlockIndex) -> Result<Block, Error> {
        self.get_block_data(block_index)
            .map(|bd| bd.block().clone())
    }

    fn get_block_contents(&self, block_index: BlockIndex) -> Result<BlockContents, Error> {
        self.get_block_data(block_index)
            .map(|bd| bd.contents().clone())
    }

    fn get_block_signature(&self, block_index: BlockIndex) -> Result<BlockSignature, Error> {
        self.get_block_data(block_index)
            .map(|bd| bd.signature().cloned().ok_or(Error::NotFound))
            .and_then(|res| res)
    }

    fn get_block_metadata(&self, block_index: BlockIndex) -> Result<BlockMetadata, Error> {
        self.get_block_data(block_index)
            .map(|bd| bd.metadata().cloned().ok_or(Error::NotFound))
            .and_then(|res| res)
    }

    fn get_block_data(&self, block_index: BlockIndex) -> Result<BlockData, Error> {
        self.lock()
            .block_data_by_index
            .get(&block_index)
            .cloned()
            .ok_or(Error::NotFound)
    }

    /// Gets block index by a TxOut global index.
    fn get_block_index_by_tx_out_index(&self, tx_out_index: u64) -> Result<BlockIndex, Error> {
        self.lock()
            .block_index_by_tx_out_index
            .get(&tx_out_index)
            .cloned()
            .ok_or(Error::NotFound)
    }

    fn num_txos(&self) -> Result<u64, Error> {
        Ok(self.lock().tx_outs.len() as u64)
    }

    fn get_tx_out_index_by_hash(&self, tx_out_hash: &[u8; 32]) -> Result<u64, Error> {
        self.lock()
            .tx_outs_by_index
            .iter()
            .find(|(_index, tx_out)| tx_out_hash == &tx_out.hash())
            .map(|(index, _)| *index)
            .ok_or(Error::NotFound)
    }

    fn get_tx_out_index_by_public_key(
        &self,
        public_key: &CompressedRistrettoPublic,
    ) -> Result<u64, Error> {
        self.lock()
            .tx_outs_by_index
            .iter()
            .find(|(_index, tx_out)| public_key == &tx_out.public_key)
            .map(|(index, _)| *index)
            .ok_or(Error::NotFound)
    }

    fn get_tx_out_by_index(&self, tx_out_index: u64) -> Result<TxOut, Error> {
        self.lock()
            .tx_outs_by_index
            .get(&tx_out_index)
            .cloned()
            .ok_or(Error::NotFound)
    }

    fn get_tx_out_proof_of_memberships(
        &self,
        _indexes: &[u64],
    ) -> Result<Vec<TxOutMembershipProof>, Error> {
        unimplemented!()
    }

    fn contains_tx_out_public_key(
        &self,
        public_key: &CompressedRistrettoPublic,
    ) -> Result<bool, Error> {
        Ok(self
            .lock()
            .tx_outs
            .iter()
            .any(|tx_out| public_key == &tx_out.public_key))
    }

    fn check_key_image(&self, key_image: &KeyImage) -> Result<Option<u64>, Error> {
        Ok(self.lock().key_images.get(key_image).cloned())
    }

    fn get_key_images_by_block(&self, block_index: BlockIndex) -> Result<Vec<KeyImage>, Error> {
        self.get_block_data(block_index)
            .map(|bd| bd.contents().key_images.clone())
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

    fn check_mint_config_tx_nonce(
        &self,
        _token_id: u64,
        _nonce: &[u8],
    ) -> Result<Option<BlockIndex>, Error> {
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
    get_mock_ledger_and_blocks(n_blocks).0
}

pub fn get_mock_ledger_and_blocks(n_blocks: usize) -> (MockLedger, Vec<BlockData>) {
    let blocks = get_test_ledger_blocks(n_blocks);
    let mut mock_ledger = MockLedger::default();
    for block_data in &blocks {
        mock_ledger
            .append_block_data(block_data)
            .expect("failed to initialize MockLedger");
    }
    (mock_ledger, blocks)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_block() {
        let blocks: [BlockData; 2] = get_test_ledger_blocks(2).try_into().unwrap();
        let [origin, block_data] = blocks;

        let mut ledger = MockLedger::default();
        ledger.append_block_data(&origin).unwrap();

        assert_eq!(1, ledger.num_blocks().unwrap());
        assert_eq!(origin, ledger.get_block_data(0).unwrap());

        assert_eq!(2, ledger.num_txos().unwrap());
        let origin_tx_out = origin.contents().outputs[0].clone();
        assert_eq!(origin_tx_out, ledger.get_tx_out_by_index(0).unwrap());

        assert_eq!(ledger.get_key_images_by_block(0).unwrap(), vec![]);

        let block_index = ledger.get_block_index_by_tx_out_index(0).unwrap();
        assert_eq!(block_index, 0);

        // === Create and append a non-origin block. ===
        ledger.append_block_data(&block_data).unwrap();

        assert_eq!(2, ledger.num_blocks().unwrap());

        // The origin block should still be in the ledger:
        assert_eq!(origin.block(), &ledger.get_block(0).unwrap());
        // The origin's TxOut should still be in the ledger:
        assert_eq!(origin_tx_out, ledger.get_tx_out_by_index(0).unwrap());

        // The new block should be in the ledger:
        assert_eq!(block_data.block(), &ledger.get_block(1).unwrap());
        assert_eq!(4, ledger.num_txos().unwrap());

        // Each TxOut from the current block should be in the ledger.
        for tx_out in &block_data.contents().outputs {
            let index = ledger
                .get_tx_out_index_by_public_key(&tx_out.public_key)
                .unwrap();
            assert_eq!(
                index,
                ledger.get_tx_out_index_by_hash(&tx_out.hash()).unwrap()
            );

            assert_eq!(&ledger.get_tx_out_by_index(index).unwrap(), tx_out);

            assert_eq!(
                block_data.block().index,
                ledger.get_block_index_by_tx_out_index(index).unwrap()
            );
        }

        let key_images = &block_data.contents().key_images;
        assert!(ledger.contains_key_image(&key_images[0]).unwrap());
        assert_eq!(key_images, &ledger.get_key_images_by_block(1).unwrap());
    }

    #[test]
    // Getting a block by index should return the correct block, if it exists.
    fn get_block_by_index() {
        let (ledger, blocks) = get_mock_ledger_and_blocks(5);

        for block_data in blocks {
            let block_index = block_data.block().index;
            let block = ledger.get_block(block_index).unwrap();
            assert_eq!(&block, block_data.block());
        }
        assert_eq!(ledger.get_block(5), Err(Error::NotFound));
    }

    #[test]
    // Getting block contents by index should return the correct block contents, if
    // that exists.
    fn get_block_contents_by_index() {
        let (ledger, blocks) = get_mock_ledger_and_blocks(5);

        for block_data in blocks {
            let block_index = block_data.block().index;
            let block_contents = ledger.get_block_contents(block_index).unwrap();
            assert_eq!(&block_contents, block_data.contents());
        }
        assert_eq!(ledger.get_block_contents(5), Err(Error::NotFound));
    }

    #[test]
    // Getting a block number by tx out index should return the correct block
    // number, if it exists.
    fn get_block_index_by_tx_out_index() {
        let (ledger, blocks) = get_mock_ledger_and_blocks(5);

        for block_data in blocks {
            let block_index = block_data.block().index;
            for tx_out in &block_data.contents().outputs {
                let tx_out_index = ledger
                    .get_tx_out_index_by_public_key(&tx_out.public_key)
                    .expect("Failed getting tx out index");

                let block_index_by_tx_out = ledger
                    .get_block_index_by_tx_out_index(tx_out_index)
                    .expect("Failed getting block index by tx out index");
                assert_eq!(block_index_by_tx_out, block_index);
            }
        }

        assert_eq!(
            ledger.get_block_index_by_tx_out_index(10),
            Err(Error::NotFound)
        );
    }

    #[test]
    // `Ledger::contains_key_image` should find key images that exist.
    fn contains_key_image() {
        let (ledger, blocks) = get_mock_ledger_and_blocks(5);

        for block_data in blocks {
            // The ledger should each key image.
            for key_image in &block_data.contents().key_images {
                assert!(ledger.contains_key_image(key_image).unwrap());
            }
        }
    }

    #[test]
    // `get_key_images_by_block` should return the correct set of key images used in
    // a single block.
    fn get_key_images_by_block() {
        let (ledger, blocks) = get_mock_ledger_and_blocks(5);

        for block_data in blocks {
            let block_index = block_data.block().index;
            assert_eq!(
                block_data.contents().key_images,
                ledger.get_key_images_by_block(block_index).unwrap()
            );
        }
    }
}
