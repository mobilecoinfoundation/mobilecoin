// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::BlockPublisher;
use futures::{Future, Stream, StreamExt};
use mc_common::logger::Logger;
use mc_crypto_keys::Ed25519Pair;
use mc_ledger_streaming_api::{
    make_subscribe_response, streaming_blocks::SubscribeResponse, BlockStreamComponents,
};
use mc_util_grpc::ConnectionUriGrpcioServer;
use mc_util_uri::ConnectionUri;
use std::sync::{Arc, RwLock};

// A sink that consumes a block stream and publishes the results over gRPC.
pub struct GrpcServerSink {
    publisher: Arc<RwLock<BlockPublisher>>,
    signer: Arc<RwLock<Ed25519Pair>>,
    logger: Logger,
}

impl GrpcServerSink {
    pub fn new(signer: Ed25519Pair, logger: Logger) -> Self {
        Self {
            publisher: Arc::new(RwLock::new(BlockPublisher::new(logger.clone()))),
            signer: Arc::new(RwLock::new(signer)),
            logger,
        }
    }

    pub fn consume<'a>(
        &mut self,
        stream: impl Stream<Item = BlockStreamComponents> + 'a,
    ) -> impl Future<Output = ()> + 'a {
        let signer = self.signer.clone();
        self.consume_protos(stream.map(move |data| {
            make_subscribe_response(&data, &signer.read().unwrap())
                .expect("Failed to create SubscribeResponse")
        }))
    }

    pub fn consume_protos<'a>(
        &mut self,
        stream: impl Stream<Item = SubscribeResponse> + 'a,
    ) -> impl Future<Output = ()> + 'a {
        let publisher = self.publisher.clone();
        stream.for_each(move |data| publisher.write().unwrap().publish(data))
    }

    pub fn create_server(
        &mut self,
        uri: &impl ConnectionUri,
        env: Arc<grpcio::Environment>,
    ) -> grpcio::Result<grpcio::Server> {
        grpcio::ServerBuilder::new(env)
            .register_service(self.publisher.write().unwrap().create_service())
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
            .spawn(sink.consume_protos(receiver))
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
                sender.try_send(response.clone()).expect("send failed");

                let mut client_2 = TestClient::new(&uri, env.clone());
                client_2.subscribe().await;

                response
                    .mut_result()
                    .mut_block()
                    .mut_v1()
                    .mut_block()
                    .set_index(1);
                sender.try_send(response.clone()).expect("send failed");

                let mut client_3 = TestClient::new(&uri, env.clone());
                client_3.subscribe().await;

                response
                    .mut_result()
                    .mut_block()
                    .mut_v1()
                    .mut_block()
                    .set_index(2);
                sender.try_send(response.clone()).expect("send failed");

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
