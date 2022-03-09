use futures::{Future, StreamExt};
use mc_ledger_streaming_api::{
    streaming_blocks::{SubscribeRequest, SubscribeResponse},
    streaming_blocks_grpc::LedgerUpdatesClient,
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::ConnectionUri;
use std::sync::{Arc, Mutex};

// Using String as the error type as grpcio::Error is not Clone-able.
pub type Response = Result<SubscribeResponse, String>;
pub type Responses = Vec<Response>;

pub struct TestClient {
    client: LedgerUpdatesClient,
    responses: Arc<Mutex<Responses>>,
}

impl TestClient {
    pub fn new(uri: &impl ConnectionUri, env: Arc<grpcio::Environment>) -> Self {
        let channel = grpcio::ChannelBuilder::default_channel_builder(env).connect(&uri.addr());
        let client = LedgerUpdatesClient::new(channel);
        Self {
            client,
            responses: Arc::new(Mutex::new(Responses::new())),
        }
    }

    /// Subscribe to the service.
    /// Returns a Future that must be invoked for the subscription to work.
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

    pub fn response_count(&self) -> usize {
        self.responses.lock().expect("mutex poisoned").len()
    }

    pub fn responses(&self) -> Responses {
        self.responses.lock().expect("mutex poisoned").clone()
    }
}
