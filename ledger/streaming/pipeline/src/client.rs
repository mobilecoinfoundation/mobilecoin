// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Helpers for client pipelines.

use mc_common::{logger::Logger, NodeID};
use mc_ledger_db::Ledger;
use mc_ledger_streaming_api::{BlockData, BlockIndex, Fetcher, Result};
use mc_ledger_streaming_client::{
    BackfillingStream, BlockValidator, DbStream, GrpcBlockSource, QuorumSet, SCPValidator,
};
use std::{collections::HashMap, ops::Range};

/// Construct a consensus client pipeline, collecting from multiple gRPC
/// servers, running validation and SCP on those gRPC streams, and writing to
/// the Ledger.
pub fn consensus_client<
    L: Ledger + Clone,
    F: Fetcher<Result<BlockData>, BlockIndex, Range<BlockIndex>>,
>(
    upstreams: HashMap<NodeID, BackfillingStream<GrpcBlockSource, F>>,
    quorum_set: QuorumSet<NodeID>,
    ledger: L,
    logger: Logger,
) -> DbStream<SCPValidator<BlockValidator<BackfillingStream<GrpcBlockSource, F>, L>>, L> {
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
