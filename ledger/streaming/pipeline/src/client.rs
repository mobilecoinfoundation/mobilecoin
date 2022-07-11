// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Helpers for client pipelines.

use mc_common::{logger::Logger, NodeID};
use mc_ledger_db::LedgerDB;
use mc_ledger_streaming_api::{BlockData, BlockIndex, Fetcher, Result};
use mc_ledger_streaming_client::{
    BackfillingStream, BlockValidator, DbStream, GrpcBlockSource, QuorumSet, SCPValidator,
};
use std::ops::Range;

/// Construct a consensus client pipeline, collecting from multiple gRPC
/// servers, running validation and SCP on those gRPC streams, and writing to
/// the Ledger.
pub fn consensus_client<F: Fetcher<Result<BlockData>, BlockIndex, Range<BlockIndex>>>(
    upstreams: impl IntoIterator<Item = (NodeID, BackfillingStream<GrpcBlockSource, F>)>,
    quorum_set: QuorumSet<NodeID>,
    ledger: LedgerDB,
    logger: Logger,
) -> DbStream<SCPValidator<BlockValidator<BackfillingStream<GrpcBlockSource, F>, LedgerDB>>, LedgerDB>
{
    let grpc_sources = upstreams
        .into_iter()
        .map(|(id, backfilling_stream)| {
            (
                id,
                BlockValidator::new(backfilling_stream, Some(ledger.clone()), logger.clone()),
            )
        })
        .collect();
    let scp_stream = SCPValidator::new(grpc_sources, quorum_set, logger.clone());
    DbStream::new(scp_stream, ledger, true, logger)
}
