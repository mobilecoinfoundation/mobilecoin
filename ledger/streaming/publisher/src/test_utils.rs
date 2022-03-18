// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Helpers for testing publishers.

use futures::{Future, StreamExt};
use mc_ledger_streaming_api::{
    streaming_blocks::{SubscribeRequest, SubscribeResponse},
    streaming_blocks_grpc::LedgerUpdatesClient,
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::ConnectionUri;
use std::sync::{Arc, Mutex};

/// A [LedgerUpdates] response frame.
// Using String as the error type as grpcio::Error is not Clone-able.
pub type Response = Result<SubscribeResponse, String>;

/// A list of [Response]s.
pub type Responses = Vec<Response>;

/// A test
pub struct TestClient {
    client: LedgerUpdatesClient,
    responses: Arc<Mutex<Responses>>,
}

impl TestClient {
    /// Instantiate a test client with the given URI and Environment.
    pub fn new(uri: &impl ConnectionUri, env: Arc<grpcio::Environment>) -> Self {
        let channel = grpcio::ChannelBuilder::default_channel_builder(env).connect(&uri.addr());
        let client = LedgerUpdatesClient::new(channel);
        Self {
            client,
            responses: Arc::new(Mutex::new(Responses::new())),
        }
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
            let mut responses = responses.lock().expect("mutex poisoned");
            responses.push(resp.map_err(|e| e.to_string()));
            futures::future::ready(())
        })
    }

    /// Get the number of subscribe responses.
    pub fn response_count(&self) -> usize {
        self.responses.lock().expect("mutex poisoned").len()
    }

    /// Get the subscribe [Responses].
    pub fn responses(&self) -> Responses {
        self.responses.lock().expect("mutex poisoned").clone()
    }
}
