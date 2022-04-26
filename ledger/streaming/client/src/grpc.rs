// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A [BlockStream] that streams blocks using the `LedgerUpdates` gRPC API.

use displaydoc::Display;
use futures::{Stream, StreamExt};
use mc_common::logger::{log, o, Logger};
use mc_ledger_streaming_api::{
    streaming_blocks::SubscribeRequest, streaming_blocks_grpc::LedgerUpdatesClient, ArchiveBlock,
    BlockData, BlockStream, Result,
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::ConnectionUri;
use std::{convert::TryFrom, sync::Arc, time::Duration};

/// A [BlockStream] that streams blocks using the `LedgerUpdates` gRPC API.
#[derive(Display)]
pub struct GrpcBlockSource {
    /// The gRPC client
    client: LedgerUpdatesClient,
    /// A logger object
    logger: Logger,
}

impl GrpcBlockSource {
    /// Instantiate a [GrpcBlockSource] pulling from the given `uri`.
    pub fn new(uri: &impl ConnectionUri, env: Arc<grpcio::Environment>, logger: Logger) -> Self {
        let logger = logger.new(o!("uri" => uri.to_string()));
        let channel =
            grpcio::ChannelBuilder::default_channel_builder(env).connect_to_uri(uri, &logger);
        let client = LedgerUpdatesClient::new(channel);
        Self { client, logger }
    }

    /// Make the Subscribe gRPC call.
    pub fn subscribe(
        &self,
        starting_height: u64,
    ) -> grpcio::Result<grpcio::ClientSStreamReceiver<ArchiveBlock>> {
        // Set up request.
        let mut req = SubscribeRequest::new();
        req.starting_height = starting_height;

        // TODO: Make timeout configurable.
        let opt = grpcio::CallOption::default().timeout(Duration::from_secs(10));

        self.client.subscribe_opt(&req, opt)
    }
}

impl BlockStream for GrpcBlockSource {
    type Stream<'s> = impl Stream<Item = Result<BlockData>> + 's;

    fn get_block_stream(&self, starting_height: u64) -> Result<Self::Stream<'_>> {
        use futures::stream::iter;

        let logger = &self.logger;
        let stream = self.subscribe(starting_height)?;
        let result = stream.flat_map(move |result| {
            log::trace!(
                logger,
                "GrpcBlockSource got {}",
                match &result {
                    Ok(block) => {
                        format!(
                            "block with index {}",
                            block.get_v1().get_block().get_index()
                        )
                    }
                    Err(err) => format!("error: {}", err),
                }
            );
            match result {
                Ok(archive_block) => {
                    let result = BlockData::try_from(&archive_block).map_err(Into::into);
                    iter([result]).left_stream()
                }
                Err(err) => iter([Err(err.into())]).right_stream(),
            }
        });
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::setup_test_server;
    use futures::{executor::block_on, future::ready};
    use mc_common::logger::test_with_logger;
    use mc_ledger_streaming_api::{test_utils::make_responses, Error};

    #[test_with_logger]
    fn basic(logger: Logger) {
        let responses = make_responses(3);
        let (_server, uri, env) = setup_test_server(responses, None, None);
        let source = GrpcBlockSource::new(&uri, env, logger.clone());

        let result_fut = source
            .get_block_stream(0)
            .expect("Failed to start block stream")
            .map(|result| {
                let block_data = result.expect("Error decoding block data");
                block_data.block().index
            })
            .collect();

        let result: Vec<u64> = block_on(result_fut);
        assert_eq!(result, &[0, 1, 2])
    }

    #[test_with_logger]
    fn propagates_errors(logger: Logger) {
        let mut responses = make_responses(2);
        responses.push(Err(Error::Grpc("meh".to_owned())).into());

        let (_server, uri, env) = setup_test_server(responses, None, None);
        let source = GrpcBlockSource::new(&uri, env, logger);

        let mut got_error = false;
        let result_fut = source
            .get_block_stream(0)
            .expect("Failed to start block stream")
            .filter_map(|resp| match resp {
                Ok(block_data) => ready(Some(block_data.block().index)),
                Err(_) => {
                    got_error = true;
                    ready(None)
                }
            })
            .collect();

        let result: Vec<u64> = block_on(result_fut);
        assert_eq!(result, &[0, 1]);

        assert!(got_error, "Expected an error response");
    }
}
