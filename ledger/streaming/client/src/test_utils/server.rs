// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mock [LedgerUpdates] server for tests.

use futures::{FutureExt, StreamExt};
use mc_ledger_streaming_api::{
    streaming_blocks::SubscribeRequest,
    streaming_blocks_grpc::{create_ledger_updates, LedgerUpdates},
    test_utils::Responses,
    ArchiveBlock,
};
use mc_util_uri::ConnectionUri;
use std::{str::FromStr, sync::Arc};

/// Test helper: Set up a local [LedgerUpdates] server serving the given
/// [Responses].
pub fn setup_test_server(
    responses: Responses,
    // Allows `None`, `Ok(42)`, or simply `42`.
    port: impl Into<Option<u16>>,
    env: Option<Arc<grpcio::Environment>>,
) -> (grpcio::Server, impl ConnectionUri, Arc<grpcio::Environment>) {
    let env =
        env.unwrap_or_else(|| Arc::new(grpcio::EnvBuilder::new().name_prefix("test").build()));
    let mut server = MockLedgerUpdates::new(responses)
        .into_server(env.clone(), port)
        .expect("Failed to initialize mock server");
    server.start();

    let (host, port) = server
        .bind_addrs()
        .next()
        .expect("Failed to get mock server address");
    let uri = mc_util_uri::ConsensusPeerUri::from_str(&format!("insecure-mcp://{}:{}", host, port))
        .expect("Failed to parse URI");
    (server, uri, env)
}

/// Mock implementation of [LedgerUpdates] serving the specified [Responses].
#[derive(Clone, Debug)]
pub struct MockLedgerUpdates {
    /// The [Responses].
    pub responses: Responses,
}

impl MockLedgerUpdates {
    /// Instantiate this type
    pub fn new(responses: Responses) -> Self {
        Self { responses }
    }

    /// Create a [grpcio::Service] implementing [LedgerUpdates]
    pub fn into_service(self) -> grpcio::Service {
        create_ledger_updates(self)
    }

    /// Create a [grpcio::Server] with a Service implementing [LedgerUpdates]
    pub fn into_server(
        self,
        env: Arc<grpcio::Environment>,
        // Allows `None`, `Ok(42)`, or simply `42`.
        port: impl Into<Option<u16>>,
    ) -> grpcio::Result<grpcio::Server> {
        grpcio::ServerBuilder::new(env)
            .register_service(self.into_service())
            .bind("localhost", port.into().unwrap_or_default())
            .build()
    }
}

impl LedgerUpdates for MockLedgerUpdates {
    fn subscribe(
        &mut self,
        ctx: grpcio::RpcContext,
        _req: SubscribeRequest,
        sink: grpcio::ServerStreamingSink<ArchiveBlock>,
    ) {
        // The sink requires WriteFlags in addition to the value.
        let responses = self
            .responses
            .iter()
            .cloned()
            .map(|r| r.with_write_flags(grpcio::WriteFlags::default()))
            // Collect to avoid an error like "`self` has an anonymous lifetime
            // `'_` but it needs to satisfy a `'static` lifetime requirement"
            .collect::<Vec<_>>();
        let stream = futures::stream::iter(responses);
        let out = stream.forward(sink).map(|_| ());
        ctx.spawn(out)
    }
}
