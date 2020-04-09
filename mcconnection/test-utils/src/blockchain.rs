// Copyright (c) 2018-2020 MobileCoin Inc.

//! Connection mock and test utilities

use ledger_db::{test_utils::MockLedger, Ledger};
use mcconnection::{
    BlockchainConnection, Connection, Error as ConnectionError, Result as ConnectionResult,
    UserTxConnection,
};
use mcuri::{ConnectionUri, ConsensusClientUri};
use std::{
    cmp::{min, Ordering},
    fmt::{Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    ops::Range,
    thread,
    time::Duration,
};
use transaction::{tx::Tx, Block, BlockID, BlockIndex};

#[derive(Clone)]
pub struct MockBlockchainConnection {
    /// The destination uri
    pub uri: ConsensusClientUri,

    /// The mock ledger to be used when serving blockchain objects
    pub ledger: MockLedger,

    /// Additional latency added to be added requests to this peer
    pub latency_millis: u64,
}

impl MockBlockchainConnection {
    pub fn new(uri: ConsensusClientUri, ledger: MockLedger, latency_millis: u64) -> Self {
        Self {
            uri,
            ledger,
            latency_millis,
        }
    }
}

impl Display for MockBlockchainConnection {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.uri())
    }
}

impl Eq for MockBlockchainConnection {}

impl Hash for MockBlockchainConnection {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.uri.addr().hash(state);
    }
}

impl Ord for MockBlockchainConnection {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uri.addr().cmp(&other.uri.addr())
    }
}

impl PartialEq for MockBlockchainConnection {
    fn eq(&self, other: &MockBlockchainConnection) -> bool {
        self.uri.addr() == other.uri.addr()
    }
}

impl PartialOrd for MockBlockchainConnection {
    fn partial_cmp(&self, other: &MockBlockchainConnection) -> Option<Ordering> {
        self.uri.addr().partial_cmp(&other.uri.addr())
    }
}

impl Connection for MockBlockchainConnection {
    type Uri = ConsensusClientUri;

    fn uri(&self) -> Self::Uri {
        self.uri.clone()
    }
}

impl BlockchainConnection for MockBlockchainConnection {
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
        unimplemented!()
    }
}

impl UserTxConnection for MockBlockchainConnection {
    fn propose_tx(&mut self, _tx: &Tx) -> ConnectionResult<BlockIndex> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_client_uri;
    use ledger_db::test_utils::get_mock_ledger;

    #[test]
    // Mock peer should return the correct range of blocks.
    fn fetch_blocks() {
        let mock_ledger = get_mock_ledger(25);
        assert_eq!(mock_ledger.lock().blocks_by_block_number.len(), 25);
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
            // Get blocks 25,26,27. These are entirely out of range, so should return an error.
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
