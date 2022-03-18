// Copyright (c) 2018-2022 The MobileCoin Foundation

use flo_stream::{ExpiringPublisher, MessagePublisher, Subscriber};
use futures::{future::BoxFuture, FutureExt, StreamExt};
use grpcio::ServerStreamingSink;
use mc_common::logger::Logger;
use mc_ledger_streaming_api::{
    streaming_blocks::{SubscribeRequest, SubscribeResponse},
    streaming_blocks_grpc::{create_ledger_updates, LedgerUpdates},
};

/// A helper for publishing blocks to multiple gRPC streams.
pub struct BlockPublisher {
    publisher: ExpiringPublisher<SubscribeResponse>,
}

impl BlockPublisher {
    /// Instantiate a publisher.
    pub fn new(_logger: Logger) -> Self {
        let publisher = ExpiringPublisher::new(3); // buffer a few responses.
        Self { publisher }
    }

    /// Publish a `SubscribeResponse` to all current subscribers.
    /// The returned value is a `Future` where the `Output` type is `()`; it is
    /// executed entirely for its side effects.
    pub fn publish(&mut self, response: SubscribeResponse) -> BoxFuture<'static, ()> {
        self.publisher.publish(response)
    }

    /// Create a `LedgerUpdates` handler.
    pub fn create_handler(&mut self) -> impl LedgerUpdates + Clone + Send + Sync + 'static {
        PublishHelper::new(self.publisher.subscribe())
    }

    /// Create a Service with a `LedgerUpdates` handler.
    pub fn create_service(&mut self) -> grpcio::Service {
        create_ledger_updates(self.create_handler())
    }
}

#[derive(Clone)]
struct PublishHelper {
    subscriber: Subscriber<SubscribeResponse>,
}

impl PublishHelper {
    pub fn new(subscriber: Subscriber<SubscribeResponse>) -> Self {
        Self { subscriber }
    }
}

impl LedgerUpdates for PublishHelper {
    fn subscribe(
        &mut self,
        ctx: grpcio::RpcContext,
        req: SubscribeRequest,
        sink: ServerStreamingSink<SubscribeResponse>,
    ) {
        let starting_height = req.starting_height;
        let stream = self
            .subscriber
            .clone()
            .skip_while(move |resp| {
                let block_index = resp
                    .get_result()
                    .get_block()
                    .get_v1()
                    .get_block()
                    .get_index();
                futures::future::ready(block_index < starting_height)
            })
            .map(|resp| Ok((resp, grpcio::WriteFlags::default())));
        let fut = stream.forward(sink).map(|_| ());
        ctx.spawn(fut);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestClient;
    use futures::task::SpawnExt;
    use mc_common::logger::test_with_logger;
    use mc_util_uri::ConsensusPeerUri;
    use std::{str::FromStr, sync::Arc};

    fn create_local_server(
        publisher: &mut BlockPublisher,
        env: Arc<grpcio::Environment>,
    ) -> (grpcio::Server, ConsensusPeerUri) {
        let server = grpcio::ServerBuilder::new(env)
            .register_service(publisher.create_service())
            .bind("localhost", 0)
            .build()
            .expect("Failed to create server");
        let port = server
            .bind_addrs()
            .map(|(_, port)| port)
            .next()
            .expect("Failed to get server port");
        let uri = ConsensusPeerUri::from_str(&format!("insecure-mcp://localhost:{}", port))
            .expect("Failed to parse local server URL");
        (server, uri)
    }

    async fn exercise_fanout(logger: Logger) {
        let mut publisher = BlockPublisher::new(logger.clone());
        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("test-publisher")
                .build(),
        );
        let (_server, uri) = create_local_server(&mut publisher, env.clone());
        let mut client_1 = TestClient::new(&uri, env.clone());
        client_1.subscribe().await;
        let mut response = SubscribeResponse::new();
        response
            .mut_result()
            .mut_block()
            .mut_v1()
            .mut_block()
            .set_index(0);
        publisher.publish(response.clone()).await;

        let mut client_2 = TestClient::new(&uri, env.clone());
        client_2.subscribe().await;

        response
            .mut_result()
            .mut_block()
            .mut_v1()
            .mut_block()
            .set_index(1);
        publisher.publish(response.clone()).await;

        let mut client_3 = TestClient::new(&uri, env.clone());
        client_3.subscribe().await;

        response
            .mut_result()
            .mut_block()
            .mut_v1()
            .mut_block()
            .set_index(2);
        publisher.publish(response).await;

        assert_eq!(3, client_1.response_count());
        assert_eq!(2, client_2.response_count());
        assert_eq!(1, client_3.response_count());
    }

    #[test_with_logger]
    fn test_futures_threadpool(logger: Logger) {
        let executor = futures::executor::ThreadPool::new().expect("Failed to create ThreadPool");
        executor
            .spawn(exercise_fanout(logger))
            .expect("Failed to spawn task");
    }

    #[test_with_logger]
    fn test_tokio_current_thread(logger: Logger) {
        let executor = async_executors::TokioCtBuilder::new()
            .build()
            .expect("Failed to create tokio runtime");
        executor
            .spawn(exercise_fanout(logger))
            .expect("Failed to spawn task");
    }

    #[test_with_logger]
    fn test_tokio_multi_thread(logger: Logger) {
        let executor = async_executors::TokioTpBuilder::new()
            .build()
            .expect("Failed to create tokio runtime");
        executor
            .spawn(exercise_fanout(logger))
            .expect("Failed to spawn task");
    }

    #[test_with_logger]
    fn test_async_std(logger: Logger) {
        let executor = async_executors::AsyncStd::new();
        executor
            .spawn(exercise_fanout(logger))
            .expect("Failed to spawn task");
    }
}
