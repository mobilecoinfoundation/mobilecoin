// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Common connection manager implementation

use crate::{sync::SyncConnection, traits::Connection};
use mc_common::{
    logger::{o, Logger},
    ResponderId,
};
use mc_util_uri::ConnectionUri;
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock, RwLockReadGuard},
};

struct ConnectionManagerInner<C: Connection> {
    /// Map of responder id -> retryable connection.
    id_to_conn: BTreeMap<ResponderId, SyncConnection<C>>,
}

/// A connection manager manages a list of peers it is connected to.
pub struct ConnectionManager<C: Connection> {
    inner: Arc<RwLock<ConnectionManagerInner<C>>>,
}

impl<C: Connection> Clone for ConnectionManager<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// A collection of connections
impl<C: Connection> ConnectionManager<C> {
    pub fn new(conns: Vec<C>, logger: Logger) -> Self {
        Self {
            inner: Arc::new(RwLock::new(ConnectionManagerInner {
                id_to_conn: conns
                    .into_iter()
                    .map(|conn| {
                        let name = conn.to_string();
                        let responder_id = conn.uri().responder_id().unwrap_or_else(|_| {
                            panic!(
                                "Could not create responder_id from {:?}",
                                conn.uri().to_string()
                            )
                        });
                        let sync_conn =
                            SyncConnection::new(conn, logger.new(o!("mc.peers.peer_name" => name)));
                        (responder_id, sync_conn)
                    })
                    .collect(),
            })),
        }
    }

    fn read(&self) -> RwLockReadGuard<ConnectionManagerInner<C>> {
        self.inner.read().expect("ConnectionManager lock poisoned")
    }

    /// Retrieve a vector of all the connection URLs owned by this manager.
    pub fn responder_ids(&self) -> Vec<ResponderId> {
        self.read().id_to_conn.keys().cloned().collect()
    }

    /// Retrieve an array of synchronous connection supports.
    pub fn conns(&self) -> Vec<SyncConnection<C>> {
        self.read().id_to_conn.values().cloned().collect()
    }

    /// Retrieve a map of URLs to the connection type.
    pub fn id_to_conn(&self) -> BTreeMap<ResponderId, SyncConnection<C>> {
        self.read().id_to_conn.clone()
    }

    /// Retrieve a given connection by ResponderId.
    pub fn conn(&self, responder_id: &ResponderId) -> Option<SyncConnection<C>> {
        self.read().id_to_conn.get(responder_id).cloned()
    }

    /// Retrieve a count of the number connections we're aware of.
    pub fn len(&self) -> usize {
        self.read().id_to_conn.len()
    }

    /// Check whether there any connections or not.
    pub fn is_empty(&self) -> bool {
        self.read().id_to_conn.is_empty()
    }
}
