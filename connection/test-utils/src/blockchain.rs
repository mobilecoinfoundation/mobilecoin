// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Connection mock and test utilities

use mc_blockchain_types::{Block, BlockID, BlockIndex, BlockVersion};
use mc_connection::{
    BlockInfo, BlockchainConnection, Connection, Error as ConnectionError,
    Result as ConnectionResult, UserTxConnection,
};
use mc_consensus_enclave_api::FeeMap;
use mc_ledger_db::Ledger;
use mc_transaction_core::tx::Tx;
use mc_util_uri::{ConnectionUri, ConsensusClientUri};
use std::{
    cmp::{min, Ordering},
    fmt::{Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    ops::Range,
    thread,
    time::Duration,
};

#[derive(Clone)]
pub struct MockBlockchainConnection<L: Ledger + Sync> {
    /// The destination uri
    pub uri: ConsensusClientUri,

    /// The mock ledger to be used when serving blockchain objects
    pub ledger: L,

    /// Additional latency added to be added requests to this peer
    pub latency_millis: u64,

    /// Proposed transactions.
    pub proposed_txs: Vec<Tx>,
}

impl<L: Ledger + Sync> MockBlockchainConnection<L> {
    pub fn new(uri: ConsensusClientUri, ledger: L, latency_millis: u64) -> Self {
        Self {
            uri,
            ledger,
            latency_millis,
            proposed_txs: Vec::new(),
        }
    }
}

impl<L: Ledger + Sync> Display for MockBlockchainConnection<L> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.uri())
    }
}

impl<L: Ledger + Sync> Eq for MockBlockchainConnection<L> {}

impl<L: Ledger + Sync> Hash for MockBlockchainConnection<L> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.uri.addr().hash(state);
    }
}

impl<L: Ledger + Sync> Ord for MockBlockchainConnection<L> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uri.addr().cmp(&other.uri.addr())
    }
}

impl<L: Ledger + Sync> PartialEq for MockBlockchainConnection<L> {
    fn eq(&self, other: &MockBlockchainConnection<L>) -> bool {
        self.uri.addr() == other.uri.addr()
    }
}

impl<L: Ledger + Sync> PartialOrd for MockBlockchainConnection<L> {
    fn partial_cmp(&self, other: &MockBlockchainConnection<L>) -> Option<Ordering> {
        self.uri.addr().partial_cmp(&other.uri.addr())
    }
}

impl<L: Ledger + Sync> Connection for MockBlockchainConnection<L> {
    type Uri = ConsensusClientUri;

    fn uri(&self) -> Self::Uri {
        self.uri.clone()
    }
}

impl<L: Ledger + Sync> BlockchainConnection for MockBlockchainConnection<L> {
    fn fetch_blocks(&mut self, range: Range<u64>) -> ConnectionResult<Vec<Block>> {
        thread::sleep(Duration::from_millis(self.latency_millis));

        let mut real_range = range;

        if real_range.start >= self.ledger.num_blocks().unwrap() {
            return Err(ConnectionError::NotFound);
        }

        real_range.end = min(real_range.end, self.ledger.num_blocks().unwrap());

        real_range
            .map(|block_index| {
                self.ledger
                    .get_block(block_index as u64)
                    .or(Err(ConnectionError::NotFound))
            })
            .collect::<Result<Vec<Block>, ConnectionError>>()
    }

    fn fetch_block_ids(&mut self, _range: Range<BlockIndex>) -> ConnectionResult<Vec<BlockID>> {
        unimplemented!()
    }

    fn fetch_block_height(&mut self) -> ConnectionResult<BlockIndex> {
        Ok(self.ledger.num_blocks().unwrap() - 1)
    }

    fn fetch_block_info(&mut self) -> ConnectionResult<BlockInfo> {
        Ok(BlockInfo {
            block_index: self.ledger.num_blocks().unwrap() - 1,
            minimum_fees: FeeMap::default_map(),
            network_block_version: *BlockVersion::MAX,
        })
    }
}

impl<L: Ledger + Sync> UserTxConnection for MockBlockchainConnection<L> {
    fn propose_tx(&mut self, tx: &Tx) -> ConnectionResult<BlockIndex> {
        self.proposed_txs.push(tx.clone());
        Ok(self.ledger.num_blocks().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_client_uri;
    use mc_ledger_db::test_utils::get_mock_ledger;

    #[test]
    // Mock peer should return the correct range of blocks.
    fn fetch_blocks() {
        let mock_ledger = get_mock_ledger(25);
        assert_eq!(mock_ledger.num_blocks().unwrap(), 25);
        let mut mock_peer = MockBlockchainConnection::new(test_client_uri(123), mock_ledger, 50);

        {
            // Get a subset of the peer's blocks.
            let blocks = mock_peer.fetch_blocks(0..10).unwrap();
            assert_eq!(blocks.len(), 10)
        }

        {
            // Get blocks 4,5,6,7,8,9.
            let blocks = mock_peer.fetch_blocks(4..10).unwrap();
            assert_eq!(blocks.len(), 6)
        }

        {
            // Get blocks 25,26,27. These are entirely out of range, so should return an
            // error.
            if let Ok(blocks) = mock_peer.fetch_blocks(25..28) {
                println!("Blocks: {:?}", blocks);
                panic!();
            }
        }

        {
            // Get blocks 20,21,..,29. Should return 20,21,...,24
            let blocks = mock_peer.fetch_blocks(20..30).unwrap();
            assert_eq!(blocks.len(), 5)
        }
    }
}
