// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A sink that consumes a [Stream] of [ArchiveBlock]s and publishes the
//! results over gRPC [LedgerUpdates].

use flo_stream::{ExpiringPublisher, MessagePublisher, Subscriber};
use futures::{lock::Mutex, FutureExt, Stream, StreamExt, TryStreamExt};
use grpcio::ServerStreamingSink;
use mc_common::logger::Logger;
use mc_ledger_streaming_api::{
    streaming_blocks::SubscribeRequest,
    streaming_blocks_grpc::{create_ledger_updates, LedgerUpdates},
    ArchiveBlock, Result,
};
use mc_util_grpc::ConnectionUriGrpcioServer;
use mc_util_uri::ConnectionUri;
use std::sync::Arc;

/// A sink that consumes a [Stream] of [ArchiveBlock]s and publishes the
/// results over gRPC [LedgerUpdates].
pub struct GrpcServerSink {
    publisher: Arc<Mutex<ExpiringPublisher<ArchiveBlock>>>,
    logger: Logger,
}

impl GrpcServerSink {
    /// Instantiate a sink that publishes [ArchiveBlock]s over the
    /// [LedgerUpdates] gRPC API.
    pub fn new(logger: Logger) -> Self {
        Self {
            // Buffer a few responses.
            publisher: Arc::new(Mutex::new(ExpiringPublisher::new(3))),
            logger,
        }
    }

    /// Consume a [Stream] of [ArchiveBlock]s.
    /// The returned value is a `Stream` where the `Output` type is
    /// `Result<()>`; it is executed entirely for its side effects, while
    /// propagating errors back to the caller.
    pub fn consume_protos<'a>(
        &self,
        stream: impl Stream<Item = Result<ArchiveBlock>> + 'a,
    ) -> impl Stream<Item = Result<()>> + 'a {
        let publisher = self.publisher.clone();
        stream.and_then(move |data| {
            let publisher = publisher.clone();
            async move {
                let mut publisher = publisher.lock().await;
                publisher.publish(data).await;
                Ok(())
            }
        })
    }

    /// Create a [LedgerUpdates] handler.
    pub fn create_handler(&self) -> impl LedgerUpdates + Clone + Send + Sync + 'static {
        let mut publisher = futures::executor::block_on(self.publisher.lock());
        PublishHelper::new(publisher.subscribe())
    }

    /// Create a [grpcio::Service] with a [LedgerUpdates] handler.
    pub fn create_service(&self) -> grpcio::Service {
        create_ledger_updates(self.create_handler())
    }

    /// Create a [grpcio::Server] with a [LedgerUpdates] service backed by
    /// this instance.
    pub fn create_server(
        &self,
        uri: &impl ConnectionUri,
        env: Arc<grpcio::Environment>,
    ) -> grpcio::Result<grpcio::Server> {
        grpcio::ServerBuilder::new(env)
            .register_service(self.create_service())
            .bind_using_uri(uri, self.logger.clone())
            .build()
    }

    /// Helper to create a local server.
    #[cfg(any(test, feature = "test_utils"))]
    pub fn create_local_server(
        &self,
        env: Arc<grpcio::Environment>,
    ) -> (grpcio::Server, mc_util_uri::ConsensusPeerUri) {
        use std::str::FromStr;

        let port = get_free_port();
        let uri =
            mc_util_uri::ConsensusPeerUri::from_str(&format!("insecure-mcp://localhost:{}", port))
                .expect("Failed to parse local server URL");
        let server = self
            .create_server(&uri, env)
            .expect("Failed to create server");
        (server, uri)
    }
}

#[derive(Clone)]
struct PublishHelper {
    subscriber: Subscriber<ArchiveBlock>,
}

impl PublishHelper {
    pub fn new(subscriber: Subscriber<ArchiveBlock>) -> Self {
        Self { subscriber }
    }
}

impl LedgerUpdates for PublishHelper {
    fn subscribe(
        &mut self,
        ctx: grpcio::RpcContext,
        req: SubscribeRequest,
        sink: ServerStreamingSink<ArchiveBlock>,
    ) {
        let starting_height = req.starting_height;
        let stream = self
            .subscriber
            .clone()
            .skip_while(move |resp| {
                let block_index = resp.get_v1().get_block().get_index();
                futures::future::ready(block_index < starting_height)
            })
            .map(|resp| Ok((resp, grpcio::WriteFlags::default())));
        let fut = stream.forward(sink).map(|_| ());
        ctx.spawn(fut);
    }
}

/// Heuristic for grabbing a free port.
#[cfg(any(test, feature = "test_utils"))]
pub fn get_free_port() -> u16 {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    static PORT_NR: AtomicUsize = AtomicUsize::new(0);
    PORT_NR.fetch_add(1, SeqCst) as u16 + 4242
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestClient;
    use futures::task::{Spawn, SpawnExt};
    use mc_common::logger::test_with_logger;
    use std::sync::Arc;

    fn exercise_sink<E: Spawn>(executor: &E, logger: Logger) {
        let sink = GrpcServerSink::new(logger.clone());
        let env = Arc::new(grpcio::EnvBuilder::new().name_prefix("test-sink").build());
        let (_server, uri) = sink.create_local_server(env.clone());

        let (mut sender, receiver) = futures::channel::mpsc::channel(5);
        executor
            .spawn(
                sink.consume_protos(receiver)
                    .for_each(|result| async move { result.expect("expected no errors") }),
            )
            .expect("spawn error");

        executor
            .spawn(async move {
                let mut response = ArchiveBlock::new();

                let mut client_1 = TestClient::new(&uri, env.clone());
                client_1.subscribe().await;
                response.mut_v1().mut_block().set_index(0);
                sender.try_send(Ok(response.clone())).expect("send failed");

                let mut client_2 = TestClient::new(&uri, env.clone());
                client_2.subscribe().await;

                response.mut_v1().mut_block().set_index(1);
                sender.try_send(Ok(response.clone())).expect("send failed");

                let mut client_3 = TestClient::new(&uri, env.clone());
                client_3.subscribe().await;

                response.mut_v1().mut_block().set_index(2);
                sender.try_send(Ok(response.clone())).expect("send failed");

                assert_eq!(3, client_1.response_count());
                assert_eq!(2, client_2.response_count());
                assert_eq!(1, client_3.response_count());
            })
            .expect("spawn failed");
    }

    #[test_with_logger]
    fn test_futures_threadpool(logger: Logger) {
        let executor = futures::executor::ThreadPool::new().expect("Failed to create ThreadPool");
        exercise_sink(&executor, logger);
    }

    #[test_with_logger]
    fn test_tokio_current_thread(logger: Logger) {
        let executor = async_executors::TokioCtBuilder::new()
            .build()
            .expect("Failed to create tokio runtime");
        exercise_sink(&executor, logger);
    }

    #[test_with_logger]
    fn test_tokio_multi_thread(logger: Logger) {
        let executor = async_executors::TokioTpBuilder::new()
            .build()
            .expect("Failed to create tokio runtime");
        exercise_sink(&executor, logger);
    }

    #[test_with_logger]
    fn test_async_std(logger: Logger) {
        let executor = async_executors::AsyncStd::new();
        exercise_sink(&executor, logger);
    }
}
