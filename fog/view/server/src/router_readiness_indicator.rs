// Copyright (c) 2018-2023 The MobileCoin Foundation

use mc_fog_uri::FogViewStoreUri;
use mc_util_grpc::ReadinessIndicator;
use std::sync::Arc;

/// Wrapper around a `ReadinessIndicator` that contains special `set_ready` logic that depends on
/// the readiness of a router's stores.
pub(crate) struct RouterReadinessIndicator {
    router_readiness_indicator: ReadinessIndicator,
    // TODO: Make generic so that ledger can reuse this.
    stores_uris : Arc<FogViewStoreUri>,
}

impl RouterReadinessIndicator {



}