// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{LedgerSyncError, NetworkState};
use mockall::*;

#[automock]
pub trait LedgerSync<NS: NetworkState + Send + Sync + 'static> {
    /// Returns true if the local ledger is behind the network's consensus view
    /// of the ledger.
    fn is_behind(&self, network_state: &NS) -> bool;

    /// Attempts to synchronize the local ledger with the consensus view of the
    /// network. # Arguments
    /// * `network_state` - Current state of the network.
    /// * `limit` - Maximum number of blocks to add to the ledger.
    fn attempt_ledger_sync(
        &mut self,
        network_state: &NS,
        limit: u32,
    ) -> Result<(), LedgerSyncError>;
}
