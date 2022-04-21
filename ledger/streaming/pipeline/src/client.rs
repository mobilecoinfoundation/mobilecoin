// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Helpers for client pipelines.

use grpcio::Environment;
use mc_common::{logger::Logger, NodeID};
use mc_ledger_db::Ledger;
use mc_ledger_streaming_api::{BlockData, BlockIndex, Fetcher, Result};
use mc_ledger_streaming_client::{
    BackfillingStream, BlockValidator, DbStream, GrpcBlockSource, QuorumSet, SCPValidator,
};
use mc_util_uri::ConnectionUri;
use std::{collections::HashMap, ops::Range, sync::Arc};

/// Construct a consensus client pipeline, collecting from multiple gRPC
/// servers, running validation and SCP on those gRPC streams, and writing to
/// the Ledger.
pub fn consensus_client<
    L: Ledger + Clone,
    F: Fetcher<Result<BlockData>, BlockIndex, Range<BlockIndex>>,
    U: ConnectionUri,
>(
    grpc_uris: HashMap<NodeID, U>,
    quorum_set: QuorumSet<NodeID>,
    client_env: Arc<Environment>,
    fetcher: F,
    ledger: L,
    logger: Logger,
) -> DbStream<BackfillingStream<SCPValidator<BlockValidator<GrpcBlockSource, L>>, F>, L> {
    let grpc_sources = grpc_uris
        .into_iter()
        .map(|(id, uri)| {
            (
                id,
                BlockValidator::new(
                    GrpcBlockSource::new(&uri, client_env.clone(), logger.clone()),
                    Some(ledger.clone()),
                    logger.clone(),
                ),
            )
        })
        .collect();
    let scp_stream = SCPValidator::new(grpc_sources, quorum_set, logger.clone());
    let backfilling_source = BackfillingStream::new(scp_stream, fetcher, logger.clone());
    DbStream::new(backfilling_source, ledger, true, logger)
}
