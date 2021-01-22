// Copyright (c) 2018-2021 The MobileCoin Foundation

//! User Transaction Connection Mock

use mc_connection::{Connection, Result as ConnectionResult, UserTxConnection};
use mc_transaction_core::{tx::Tx, BlockIndex};
use mc_util_uri::{ConnectionUri, ConsensusClientUri};
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};

#[derive(Clone)]
pub struct MockUserTxConnection {
    uri: ConsensusClientUri,
    pub submitted_txs: Vec<Tx>,
}

impl MockUserTxConnection {
    pub fn new(uri: ConsensusClientUri) -> Self {
        MockUserTxConnection {
            uri,
            submitted_txs: Vec::new(),
        }
    }
}

impl Display for MockUserTxConnection {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.uri())
    }
}

impl Eq for MockUserTxConnection {}

impl Hash for MockUserTxConnection {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.uri.addr().hash(state);
    }
}

impl Ord for MockUserTxConnection {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uri.addr().cmp(&other.uri.addr())
    }
}

impl PartialEq for MockUserTxConnection {
    fn eq(&self, other: &MockUserTxConnection) -> bool {
        self.uri.addr() == other.uri.addr()
    }
}

impl PartialOrd for MockUserTxConnection {
    fn partial_cmp(&self, other: &MockUserTxConnection) -> Option<Ordering> {
        self.uri.addr().partial_cmp(&other.uri.addr())
    }
}

impl Connection for MockUserTxConnection {
    type Uri = ConsensusClientUri;

    fn uri(&self) -> Self::Uri {
        self.uri.clone()
    }
}

impl UserTxConnection for MockUserTxConnection {
    fn propose_tx(&mut self, tx: &Tx) -> ConnectionResult<BlockIndex> {
        self.submitted_txs.push(tx.clone());
        Ok(1)
    }
}
