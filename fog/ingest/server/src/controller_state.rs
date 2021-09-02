// Copyright (c) 2018-2021 The MobileCoin Foundation

//! IngestControllerState represents what the ingest server is currently trying
//! to do

use crate::{counters, server::IngestServerConfig, SeqDisplay};
use displaydoc::Display;
use mc_common::logger::{log, Logger};
use mc_fog_api::ingest_common::{IngestControllerMode, IngestSummary};
use mc_fog_recovery_db_iface::IngestInvocationId;
use mc_fog_uri::IngestPeerUri;
use mc_transaction_core::BlockIndex;
use std::{collections::BTreeSet, fmt::Display};

/// The ingest server is, at any time, in one of two modes:
///
/// Idle: Not currently consuming TxOut's from the blockchain, nor publishing
/// fog reports Active: Currently consuming TxOut's from consecutive blocks of
/// the blockchain and publishing fog reports
///
/// Idle -> Active: This transition happens when the server is asked to start
/// via grpc Active -> Idle: This transition happens when we try to publish a
/// report after scanning a block,                 and learn that the key is
/// marked "retired" and the pubkey_expiry block has already
/// been scanned, so there is nothing more to do with this key.
#[derive(Copy, Clone, Display, Debug, PartialEq, Eq)]
pub enum IngestMode {
    /// Idle
    Idle,
    /// Active
    Active,
}

/// State controlling the operation of the ingest controller.
///
/// This data is set from the server configuration initially, but then can be
/// changed via admin API etc. The next_block_index is incremented every time a
/// block is processed.
///
/// This class permits shared access to the data and contains some
/// synchronziation primitives, but doesn't expose that to the caller for
/// simplicity.
///
/// This class enforces some rules like, next_block_index cannot be changed
/// while the server is actively scanning for blocks.
///
/// This state includes
/// - what mode are we in: idle, active, retiring
/// - what is the next block that should be processed
/// - what is the pubkey_expiry_window (the number of blocks for which a fog
///   report is valid)
///
/// Most of the values in here will be Atomic to allow shared access to the
/// controller state, but we provide nicer API so that we don't expose the user
/// to the Atomic API directly.
///
/// Note: When locking, if both mode and peers are needed, mode should be locked
/// first.
pub struct IngestControllerState {
    /// Whether the server is idling, actively scanning the blockchain and
    /// publishing reports, or retiring
    mode: IngestMode,
    /// The next block index to scan from
    next_block_index: u64,
    /// The value we add to the current block index to compute the pubkey expiry
    /// value in fog reports
    pubkey_expiry_window: u64,
    /// The ingest invocation id we got from the database, which tracks our kex
    /// rng pubkey
    ingest_invocation_id: Option<IngestInvocationId>,
    /// Our current set of known peers. Only one should be active at a time, the
    /// others should be backups in idle state.
    peers: BTreeSet<IngestPeerUri>,
    /// Logger
    logger: Logger,
}

impl IngestControllerState {
    /// Initialize ingest controller state from config, and a logger
    pub fn new(config: &IngestServerConfig, logger: Logger) -> Self {
        let peers = config.peers.clone();
        Self {
            mode: IngestMode::Idle,
            next_block_index: 0, // this is set when the server activates, based on DB's
            pubkey_expiry_window: config.pubkey_expiry_window,
            ingest_invocation_id: None,
            peers,
            logger,
        }
    }

    /// Are we in the idle mode
    /// In this mode, we aren't actively consuming blocks or writing to database
    pub fn is_idle(&self) -> bool {
        self.mode == IngestMode::Idle
    }

    /// Are we in the active mode
    /// In this mode, we are consuming blocks, and publishing fog reports
    pub fn is_active(&self) -> bool {
        self.mode == IngestMode::Active
    }

    /// Move the server to the active mode.
    /// This is allowed from any mode.
    ///
    /// Note: The caller should ensure that the private key is backed up among
    /// peers successfully before calling this.
    pub fn set_active(&mut self) {
        match self.mode {
            IngestMode::Active => {
                log::info!(self.logger, "Server was already in the active mode");
            }
            IngestMode::Idle => {
                log::info!(self.logger, "Server moved to active mode, scanning at block index {}, pubkey_expiry_window = {}", self.next_block_index, self.pubkey_expiry_window);
            }
        }
        self.set_mode(IngestMode::Active);
    }

    pub fn set_idle(&mut self) {
        match self.mode {
            IngestMode::Active => {
                log::info!(self.logger, "Server moved to idle from active, was scanning at block index {}, pubkey_expiry_window = {}", self.next_block_index, self.pubkey_expiry_window);
            }
            IngestMode::Idle => {
                log::info!(self.logger, "Server was already idle");
            }
        }
        self.set_mode(IngestMode::Idle);
    }

    /// Get the next block index to be loaded
    pub fn get_next_block_index(&self) -> BlockIndex {
        self.next_block_index
    }

    /// Increment the next_block_index.
    /// Call this after having scanned block and added to database
    ///
    /// Pre-condition:
    /// * We are in the active state
    pub fn increment_next_block_index(&mut self) {
        assert!(
            !self.is_idle(),
            "next_block_index should not be incremented if we are idle: {}",
            self
        );
        // Perform the increment
        self.next_block_index += 1;
        log::debug!(
            self.logger,
            "Incremented next block index: {}",
            self.next_block_index
        );
    }

    /// Set the next block index to a new value.
    /// This is only allowed if the server is in the idle state.
    pub fn set_next_block_index(&mut self, new_val: BlockIndex) -> Result<(), StateChangeError> {
        if self.mode == IngestMode::Idle {
            self.next_block_index = new_val;
            Ok(())
        } else {
            Err(StateChangeError::CannotSetNextBlockIndex(self.mode))
        }
    }

    /// Get the pubkey expiry window
    pub fn get_pubkey_expiry_window(&self) -> u64 {
        self.pubkey_expiry_window
    }

    /// Set the pubkey expiry window
    /// If the server is not idle, this can only be increased, or an error will
    /// occur.
    pub fn set_pubkey_expiry_window(&mut self, val: u64) -> Result<(), StateChangeError> {
        if self.mode == IngestMode::Idle {
            log::info!(self.logger, "pubkey_expiry_window set to {}", val);
            self.pubkey_expiry_window = val;
            Ok(())
        } else {
            let old_val = self.pubkey_expiry_window;
            if old_val > val {
                Err(StateChangeError::CannotReducePubkeyExpiry(
                    self.mode, old_val, val,
                ))
            } else {
                log::info!(self.logger, "pubkey_expiry_window set to {}", val);
                self.pubkey_expiry_window = val;
                Ok(())
            }
        }
    }

    /// Get the ingest_invocation_id
    pub fn get_ingest_invocation_id(&self) -> Option<IngestInvocationId> {
        self.ingest_invocation_id
    }

    /// Set the ingest_invocation_id
    pub fn set_ingest_invocation_id(&mut self, val: &Option<IngestInvocationId>) {
        self.ingest_invocation_id = *val;
    }

    /// Get the current set of ingest peers
    pub fn get_peers(&self) -> BTreeSet<IngestPeerUri> {
        self.peers.clone()
    }

    /// Set the list of ingest peers, and log the changes
    pub fn set_peers(&mut self, new_peers: BTreeSet<IngestPeerUri>) {
        let added: Vec<_> = new_peers.difference(&self.peers).collect();
        let removed: Vec<_> = self.peers.difference(&new_peers).collect();
        if !added.is_empty() || !removed.is_empty() {
            log::info!(
                self.logger,
                "Peers updated: Added {}, Removed {}",
                SeqDisplay(added.iter()),
                SeqDisplay(removed.iter())
            );
            self.peers = new_peers;
        }
    }

    /// Get an ingest summary protobuf object containing the data from self
    pub fn get_ingest_summary(&self) -> IngestSummary {
        let mut result = IngestSummary::new();
        match self.mode {
            IngestMode::Idle => {
                result.mode = IngestControllerMode::Idle;
            }
            IngestMode::Active => {
                result.mode = IngestControllerMode::Active;
            }
        };

        result.next_block_index = self.next_block_index;
        result.pubkey_expiry_window = self.pubkey_expiry_window;
        if let Some(iid) = self.ingest_invocation_id {
            result.ingest_invocation_id = *iid;
        }
        result.peers =
            protobuf::RepeatedField::from_vec(self.peers.iter().map(|x| x.to_string()).collect());
        result
    }

    /// Sets the current mode and update relevant metrics.
    fn set_mode(&mut self, mode: IngestMode) {
        log::info!(
            self.logger,
            "Mode switching from {:?} to {:?}",
            self.mode,
            mode
        );
        self.mode = mode;

        match self.mode {
            IngestMode::Idle => {
                counters::MODE_IS_IDLE.set(1);
                counters::MODE_IS_ACTIVE.set(0);
                counters::MODE.set(counters::MODE_IDLE);
            }
            IngestMode::Active => {
                counters::MODE_IS_IDLE.set(0);
                counters::MODE_IS_ACTIVE.set(1);
                counters::MODE.set(counters::MODE_ACTIVE);
            }
        }
    }
}

#[derive(Display, Debug)]
pub enum StateChangeError {
    /// Cannot set next_block_index unless server is idling: {0}
    CannotSetNextBlockIndex(IngestMode),
    /**
     * Cannot reduce pubkey_expiry_window unless server is idling: {0},
     * old_val = {1}, proposed_val = {2}
     */
    CannotReducePubkeyExpiry(IngestMode, u64, u64),
}

// Implement display for the object by writing its json representation
impl Display for IngestControllerState {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "{{ mode: {}, next_block_index: {}, pubkey_expiry_window: {}, ",
            self.mode, self.next_block_index, self.pubkey_expiry_window
        )?;
        if let Some(iid) = self.ingest_invocation_id {
            write!(f, "ingest_invocation_id: {}, ", iid)?;
        }
        write!(f, "peers: {} }}", SeqDisplay(self.peers.iter()))
    }
}
