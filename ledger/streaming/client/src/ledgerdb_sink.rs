use crate::{source::}
use futures::stream::{select_all, Stream, StreamExt};
use mc_common::{NodeID, logger::Logger};
use mc_ledger_streaming_api::{BlockSource, LedgerStreamingError};
use mc_ledger_streaming_client::GrpcBlockSource;
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::{Block, BlockData};
use mc_util_uri::ConnectionUri;
use std::sync::{atomic::AtomicBool, Arc};
use futures::TryStreamExt;
use crate::source::GrpcBlockSource;

/// A connection manager manages a list of peers it is connected to.
pub struct BlockSink<
    BS: Stream<Item = Result<(NodeID, BlockData), LedgerStreamingError>>,
    URI: ConnectionUri,
> {
    peers: Arc<Vec<URI>>,
    streams: Arc<Vec<BS>>,
    is_blocking_quorum_set: Arc<AtomicBool>,
    logger: Logger,
}

impl<
    BS: Stream<Item = Result<(NodeID, BlockData), LedgerStreamingError>>,
    URI: ConnectionUri>
    BlockSink<BS, URI>
{
    pub fn new(peer_nodes: Vec<URI>, logger: Logger) -> Self {
        let peers = Arc::new(peer_nodes);
        let is_blocking_quorum_set = Arc::new(AtomicBool::new(is_blocking_quorum(peers.clone())));
        Self {
            peers,
            streams: Arc::new(Vec::new()),
            is_blocking_quorum_set,
            logger
        }
    }

    // Initialize peers streams
    pub fn initialize_peer_streams(&mut self, ledger: &impl Ledger) {
        let start_height = ledger.num_blocks().unwrap();
        self.streams = self.peers.iter().map(|uri| {
            let env = grpcio::Environment::new(5);
            GrpcBlockSource::new(uri, Arc::new(env), self.logger.clone()).
                    get_block_stream(start_height, uri)
        }).collect();
    }

    // Ingest blocks from stream into a sink for processing
    async fn ingest(&self) {
        let mut block_streams = select_all(self.streams.clone());
        while let Ok(block) = block_streams.map_ok(|a| a ).try_next().await {
            //
            //
        }
    }

    // Validate the blocks
    async fn validate(&self) {

    }

    // Sink puts validated blocks in the ledgerdb
    async fn db_sink(&self) {}
}