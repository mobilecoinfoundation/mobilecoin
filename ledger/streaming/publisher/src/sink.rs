// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::BlockPublisher;
use futures::{lock::Mutex, Stream, StreamExt, TryStreamExt};
use mc_common::logger::Logger;
use mc_crypto_keys::Ed25519Pair;
use mc_ledger_streaming_api::{
    make_subscribe_response, streaming_blocks::SubscribeResponse, BlockStream,
    BlockStreamComponents, Result,
};
use mc_util_grpc::ConnectionUriGrpcioServer;
use mc_util_uri::ConnectionUri;
use std::sync::Arc;

/// A sink that consumes a block stream and publishes the results over gRPC.
pub struct GrpcServerSink {
    publisher: Arc<Mutex<BlockPublisher>>,
    signer: Arc<Mutex<Ed25519Pair>>,
    logger: Logger,
}

impl GrpcServerSink {
    /// Instantiate a sink that publishes blocks, signed with the given
    /// `signer`.
    pub fn new(signer: Ed25519Pair, logger: Logger) -> Self {
        Self {
            publisher: Arc::new(Mutex::new(BlockPublisher::new(logger.clone()))),
            signer: Arc::new(Mutex::new(signer)),
            logger,
        }
    }

    /// Consume the given `BlockStream`.
    /// The returned value is a `Stream` where the `Output` type is
    /// `Result<()>`; it is executed entirely for its side effects, while
    /// propagating errors back to the caller.
    pub fn consume<'a>(
        &mut self,
        stream: impl BlockStream + 'a,
        starting_height: u64,
    ) -> Result<impl Stream<Item = Result<()>> + 'a> {
        Ok(self.consume_components(stream.get_block_stream(starting_height)?))
    }

    /// Consume a stream of `BlockStreamComponents`.
    /// The returned value is a `Stream` where the `Output` type is
    /// `Result<()>`; it is executed entirely for its side effects, while
    /// propagating errors back to the caller.
    pub fn consume_components<'a>(
        &mut self,
        stream: impl Stream<Item = Result<BlockStreamComponents>> + 'a,
    ) -> impl Stream<Item = Result<()>> + 'a {
        let signer = self.signer.clone();
        self.consume_protos(stream.then(move |result| {
            let signer = signer.clone();
            async move {
                let data = result?;
                let signer = signer.lock().await;
                make_subscribe_response(&data, &signer)
            }
        }))
    }

    /// Consume a stream of `SubscribeResponse`.
    /// The returned value is a `Stream` where the `Output` type is
    /// `Result<()>`; it is executed entirely for its side effects, while
    /// propagating errors back to the caller.
    pub fn consume_protos<'a>(
        &mut self,
        stream: impl Stream<Item = Result<SubscribeResponse>> + 'a,
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

    /// Create a `Service` with a `LedgerUpdates` handler.
    pub fn create_service(&mut self) -> grpcio::Service {
        let mut publisher = futures::executor::block_on(self.publisher.lock());
        publisher.create_service()
    }

    /// Create a gRPC `Server` with a `LedgerUpdates` service using this
    /// instance.
    pub fn create_server(
        &mut self,
        uri: &impl ConnectionUri,
        env: Arc<grpcio::Environment>,
    ) -> grpcio::Result<grpcio::Server> {
        grpcio::ServerBuilder::new(env)
            .register_service(self.create_service())
            .bind_using_uri(uri, self.logger.clone())
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestClient;
    use futures::task::{Spawn, SpawnExt};
    use mc_common::logger::test_with_logger;
    use mc_util_from_random::FromRandom;
    use mc_util_uri::ConsensusPeerUri;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use std::{
        str::FromStr,
        sync::{
            atomic::{AtomicUsize, Ordering::SeqCst},
            Arc,
        },
    };

    fn get_free_port() -> u16 {
        static PORT_NR: AtomicUsize = AtomicUsize::new(0);
        PORT_NR.fetch_add(1, SeqCst) as u16 + 4242
    }

    fn create_local_server(
        sink: &mut GrpcServerSink,
        env: Arc<grpcio::Environment>,
    ) -> (grpcio::Server, ConsensusPeerUri) {
        let port = get_free_port();
        let uri = ConsensusPeerUri::from_str(&format!("insecure-mcp://localhost:{}", port))
            .expect("Failed to parse local server URL");
        let server = sink
            .create_server(&uri, env)
            .expect("Failed to create server");
        (server, uri)
    }

    fn exercise_sink<E: Spawn>(executor: &E, logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer = Ed25519Pair::from_random(&mut rng);
        let mut sink = GrpcServerSink::new(signer, logger.clone());
        let env = Arc::new(grpcio::EnvBuilder::new().name_prefix("test-sink").build());
        let (_server, uri) = create_local_server(&mut sink, env.clone());

        let (mut sender, receiver) = futures::channel::mpsc::channel(5);
        executor
            .spawn(
                sink.consume_protos(receiver)
                    .for_each(|result| async move { result.unwrap() }),
            )
            .expect("spawn error");

        executor
            .spawn(async move {
                let mut response = SubscribeResponse::new();

                let mut client_1 = TestClient::new(&uri, env.clone());
                client_1.subscribe().await;
                response
                    .mut_result()
                    .mut_block()
                    .mut_v1()
                    .mut_block()
                    .set_index(0);
                sender.try_send(Ok(response.clone())).expect("send failed");

                let mut client_2 = TestClient::new(&uri, env.clone());
                client_2.subscribe().await;

                response
                    .mut_result()
                    .mut_block()
                    .mut_v1()
                    .mut_block()
                    .set_index(1);
                sender.try_send(Ok(response.clone())).expect("send failed");

                let mut client_3 = TestClient::new(&uri, env.clone());
                client_3.subscribe().await;

                response
                    .mut_result()
                    .mut_block()
                    .mut_v1()
                    .mut_block()
                    .set_index(2);
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
