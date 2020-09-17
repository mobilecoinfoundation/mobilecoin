// Copyright (c) 2018-2020 MobileCoin Inc.

//! Tracks the state of peers' ledgers.

mod network_state_trait;
mod polling_network_state;
mod scp_network_state;

pub use network_state_trait::NetworkState;
pub use polling_network_state::PollingNetworkState;
pub use scp_network_state::SCPNetworkState;
