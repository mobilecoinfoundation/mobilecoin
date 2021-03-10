// Copyright (c) 2018-2021 The MobileCoin Foundation

use std::time::Instant;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerSyncState {
    /// Local ledger is in sync with the network.
    InSync,

    /// Local ledger is behind the network, but we're allowing for some time
    /// before starting catch up in case we are just about to receive SCP
    /// messages that would bring us back in sync. The `Instant` argument is
    /// when we entered this state, and is used to check when this grace
    /// period has been exceeded.
    MaybeBehind(Instant),

    /// We are behind the network and need to perform catchup.
    IsBehind {
        // Time when we should attempt to sync.
        attempt_sync_at: Instant,

        // Number of attempts made so far,
        num_sync_attempts: u64,
    },
}
