// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Helpers for testing publishers.

use futures::{
    lock::{Mutex, MutexGuard},
    Future, StreamExt,
};
use mc_ledger_streaming_api::{
    streaming_blocks::SubscribeRequest, streaming_blocks_grpc::LedgerUpdatesClient,
    test_utils::Responses,
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::ConnectionUri;
use std::sync::Arc;

/// A simple `LedgerUpdates` client that collects [Responses].
pub struct TestClient {
    client: LedgerUpdatesClient,
    responses: Arc<Mutex<Responses>>,
}

impl TestClient {
    /// Instantiate a test client with the given URI and Environment.
    pub fn new(uri: &impl ConnectionUri, env: Arc<grpcio::Environment>) -> Self {
        let channel = grpcio::ChannelBuilder::default_channel_builder(env).connect(&uri.addr());
        let client = LedgerUpdatesClient::new(channel);
        let responses = Arc::new(Mutex::new(Responses::new()));
        Self { client, responses }
    }

    /// Subscribe to the service.
    /// The returned value is a [Future] that is executed entirely for its side
    /// effects.
    pub fn subscribe(&mut self) -> impl Future<Output = ()> + '_ {
        let receiver = self
            .client
            .subscribe(&SubscribeRequest::new())
            .expect("failed to subscribe");
        let responses = self.responses.clone();
        receiver.for_each(move |resp| {
            let responses = responses.clone();
            async move {
                let mut responses = responses.lock().await;
                responses.push(resp.map_err(Into::into).into());
            }
        })
    }

    /// Get the number of subscribe responses.
    pub fn response_count(&self) -> usize {
        self.responses().len()
    }

    /// Get the subscribe [Responses].
    pub fn responses(&self) -> MutexGuard<'_, Responses> {
        futures::executor::block_on(self.responses.lock())
    }
}
