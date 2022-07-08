// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Test helpers.
#![allow(dead_code)]

use async_channel::{Receiver, Sender};
use futures::Stream;
use mc_common::{logger::Logger, NodeID};
use mc_ledger_streaming_api::{test_utils::MockStream, BlockData, Error, Result};
use mc_ledger_streaming_pipeline::LedgerToArchiveBlocksAndGrpc;
#[cfg(feature = "publisher_local")]
use mc_ledger_streaming_publisher::LocalFileProtoWriter;
use mc_ledger_streaming_publisher::ProtoWriter;
#[cfg(feature = "publisher_s3")]
use mc_ledger_streaming_publisher::{S3ClientProtoWriter, S3Region};
use mc_util_uri::ConsensusPeerUri;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tempdir::TempDir;

pub struct ConsensusNode<W: ProtoWriter> {
    pub id: NodeID,
    pub pipeline: LedgerToArchiveBlocksAndGrpc<MockStream<Receiver<Result<BlockData>>>, W>,
    pub sender: Sender<Result<BlockData>>,
    pub server: grpcio::Server,
    pub uri: ConsensusPeerUri,
}

impl<W: ProtoWriter> ConsensusNode<W> {
    pub fn make_node(id: NodeID, archive_proto_writer: W, logger: Logger) -> Self {
        let (sender, receiver) = async_channel::bounded(3);
        let upstream = MockStream::new(receiver);

        let ledger_dir = TempDir::new(&format!("consensus_node_{}", id)).unwrap();
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
        }
    }

    pub fn make_nodes(
        ids: impl IntoIterator<Item = NodeID>,
        archive_proto_writer: W,
        logger: Logger,
    ) -> Vec<Self> {
        ids.into_iter()
            .map(|id| Self::make_node(id, archive_proto_writer.clone(), logger.clone()))
            .collect()
    }

    pub fn run(&self, starting_height: u64) -> impl Stream<Item = Result<()>> + '_ {
        self.pipeline
            .run(starting_height)
            .expect("failed to start consensus node pipeline")
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
    pub fn make_local(id: NodeID, local_path: impl Into<PathBuf>, logger: Logger) -> Self {
        Self::make_node(id, LocalFileProtoWriter::new(local_path.into()), logger)
    }

    pub fn make_local_nodes(
        ids: impl IntoIterator<Item = NodeID>,
        local_path: impl Into<PathBuf>,
        logger: Logger,
    ) -> Vec<Self> {
        Self::make_nodes(ids, LocalFileProtoWriter::new(local_path.into()), logger)
    }
}

#[cfg(feature = "publisher_s3")]
impl ConsensusNode<S3ClientProtoWriter> {
    pub fn make_s3(
        id: NodeID,
        region: S3Region,
        s3_path: impl Into<PathBuf>,
        logger: Logger,
    ) -> Self {
        Self::make_node(id, S3ClientProtoWriter::new(region, s3_path.into()), logger)
    }

    pub fn make_s3_nodes(
        ids: impl IntoIterator<Item = NodeID>,
        region: S3Region,
        s3_path: impl Into<PathBuf>,
        logger: Logger,
    ) -> Vec<Self> {
        Self::make_nodes(
            ids,
            S3ClientProtoWriter::new(region, s3_path.into()),
            logger,
        )
    }
}

pub fn get_uris_by_node_id<W: ProtoWriter>(
    nodes: &[ConsensusNode<W>],
) -> HashMap<NodeID, ConsensusPeerUri> {
    nodes
        .iter()
        .map(|node| (node.id.clone(), node.uri.clone()))
        .collect()
}
