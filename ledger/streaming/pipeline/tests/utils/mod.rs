// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Test helpers.
#![allow(dead_code)]

use async_channel::{Receiver, Sender};
use futures::StreamExt;
use mc_common::{
    logger::{o, Logger},
    NodeID,
};
use mc_ledger_streaming_api::{test_utils::MockStream, BlockData, Error, Result};
use mc_ledger_streaming_client::GrpcBlockSource;
use mc_ledger_streaming_pipeline::LedgerToArchiveBlocksAndGrpc;
#[cfg(feature = "publisher_local")]
use mc_ledger_streaming_publisher::LocalFileProtoWriter;
use mc_ledger_streaming_publisher::ProtoWriter;
#[cfg(feature = "publisher_s3")]
use mc_ledger_streaming_publisher::{S3ClientProtoWriter, S3Region};
use mc_util_uri::ConsensusPeerUri;
use std::{path::PathBuf, sync::Arc};
use tempdir::TempDir;

pub struct ConsensusNode<W: ProtoWriter + 'static> {
    pub id: NodeID,
    pub pipeline: LedgerToArchiveBlocksAndGrpc<MockStream<Receiver<Result<BlockData>>>, W>,
    pub sender: Sender<Result<BlockData>>,
    pub server: grpcio::Server,
    pub uri: ConsensusPeerUri,
    pub logger: Logger,
}

impl<W: ProtoWriter + 'static> ConsensusNode<W> {
    pub fn make_node(id: NodeID, archive_proto_writer: W, logger: Logger) -> Arc<Self> {
        let responder_id_str = id.responder_id.to_string();
        let ledger_dir = TempDir::new(&format!("consensus_node_{}", &responder_id_str)).unwrap();
        let logger = logger.new(o!("responder_id" => responder_id_str));

        let (sender, receiver) = async_channel::unbounded();
        let upstream = MockStream::new(receiver);

        let pipeline = LedgerToArchiveBlocksAndGrpc::new(
            upstream,
            ledger_dir.path(),
            archive_proto_writer,
            logger.clone(),
        )
        .expect("LedgerToArchiveBlocksAndGrpc::new");

        let server_env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("ledger_streaming_test_server".to_string())
                .build(),
        );
        let (server, uri) = pipeline.grpc_sink.create_local_server(server_env);

        Self {
            id,
            pipeline,
            sender,
            server,
            uri,
            logger,
        }
        .into()
    }

    pub async fn connect(self: Arc<Self>, starting_height: u64) {
        let mut stream = Box::pin(
            self.pipeline
                .run(starting_height)
                .expect("failed to start consensus node pipeline"),
        );
        while let Some(result) = stream.next().await {
            result.expect("unexpected error in server pipeline")
        }
    }

    pub fn externalize_block(&self, block_data: BlockData) {
        self.sender
            .try_send(Ok(block_data))
            .expect("failed to send block")
    }

    pub fn externalize_error(&self, err: Error) {
        self.sender
            .try_send(Err(err))
            .expect("failed to send error")
    }

    pub async fn externalize_many(&self, blocks: impl IntoIterator<Item = Result<BlockData>>) {
        for result in blocks {
            self.sender.try_send(result).expect("failed to send block")
        }
    }

    pub fn grpc_client(&self, env: Arc<grpcio::Environment>) -> GrpcBlockSource {
        GrpcBlockSource::new(&self.uri, env, self.logger.clone())
    }
}

#[cfg(feature = "publisher_local")]
impl ConsensusNode<LocalFileProtoWriter> {
    pub fn make_local_node(
        id: NodeID,
        local_path: impl Into<PathBuf>,
        logger: Logger,
    ) -> Arc<Self> {
        Self::make_node(id, LocalFileProtoWriter::new(local_path.into()), logger)
    }

    pub fn make_local_nodes(
        ids: impl IntoIterator<Item = NodeID>,
        local_path: impl Into<PathBuf>,
        logger: Logger,
    ) -> Vec<Arc<Self>> {
        let local_path = local_path.into();
        ids.into_iter()
            .map(|id| {
                let node_dir = local_path.join(id.responder_id.to_string());
                Self::make_local_node(id, node_dir, logger.clone())
            })
            .collect()
    }
}

#[cfg(feature = "publisher_s3")]
impl ConsensusNode<S3ClientProtoWriter> {
    pub fn make_s3_node(
        id: NodeID,
        region: S3Region,
        s3_path: impl Into<PathBuf>,
        logger: Logger,
    ) -> Arc<Self> {
        Self::make_node(id, S3ClientProtoWriter::new(region, s3_path.into()), logger)
    }

    pub fn make_s3_nodes(
        ids: impl IntoIterator<Item = NodeID>,
        region: S3Region,
        s3_path: impl Into<PathBuf>,
        logger: Logger,
    ) -> Vec<Arc<Self>> {
        let s3_path = s3_path.into();
        ids.into_iter()
            .map(|id| {
                let node_dir = s3_path.join(id.responder_id.to_string());
                Self::make_s3_node(id, region.clone(), node_dir, logger.clone())
            })
            .collect()
    }
}

unsafe impl<W: ProtoWriter + 'static> Send for ConsensusNode<W> {}
unsafe impl<W: ProtoWriter + 'static> Sync for ConsensusNode<W> {}
