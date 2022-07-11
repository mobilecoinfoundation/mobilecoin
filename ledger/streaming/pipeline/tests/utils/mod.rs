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
use mc_ledger_streaming_pipeline::LedgerToArchiveBlocksAndGrpc;
#[cfg(feature = "publisher_local")]
use mc_ledger_streaming_publisher::LocalFileProtoWriter;
use mc_ledger_streaming_publisher::ProtoWriter;
#[cfg(feature = "publisher_s3")]
use mc_ledger_streaming_publisher::{S3ClientProtoWriter, S3Region};
use mc_util_uri::ConsensusPeerUri;
use std::{path::PathBuf, sync::Arc};
use tempdir::TempDir;
use tokio::runtime::Handle;

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

    pub fn make_nodes(
        ids: impl IntoIterator<Item = NodeID>,
        archive_proto_writer: W,
        logger: Logger,
    ) -> Vec<Arc<Self>> {
        ids.into_iter()
            .map(|id| Self::make_node(id, archive_proto_writer.clone(), logger.clone()))
            .collect()
    }

    pub fn add_many(
        self: &Arc<Self>,
        runtime: &Handle,
        starting_height: u64,
        blocks: impl IntoIterator<Item = Result<BlockData>>,
    ) {
        let this = Arc::clone(self);
        runtime.spawn(async move {
            let mut stream = this
                .pipeline
                .run(starting_height)
                .expect("failed to start consensus node pipeline");
            while let Some(result) = stream.next().await {
                result.expect("unexpected error in server pipeline")
            }
        });
        for result in blocks {
            self.sender.try_send(result).expect("failed to send block")
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
        Self::make_nodes(ids, LocalFileProtoWriter::new(local_path.into()), logger)
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
        Self::make_nodes(
            ids,
            S3ClientProtoWriter::new(region, s3_path.into()),
            logger,
        )
    }
}

// TODO: Is this accurate?
unsafe impl<W: ProtoWriter + 'static> Send for ConsensusNode<W> {}
unsafe impl<W: ProtoWriter + 'static> Sync for ConsensusNode<W> {}
