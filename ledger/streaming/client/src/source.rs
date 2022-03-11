// Copyright (c) 2018-2022 The MobileCoin Foundation
#![allow(dead_code)]

use displaydoc::Display;
use futures::{Stream, StreamExt};
use mc_common::logger::{log, o, Logger};
use mc_ledger_streaming_api::{
    streaming_blocks::{SubscribeRequest, SubscribeResponse},
    streaming_blocks_grpc::LedgerUpdatesClient,
    BlockSource, LedgerStreamingError, StreamResult,
};
use mc_transaction_core::BlockData;
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::ConnectionUri;
use std::{convert::TryFrom, sync::Arc, time::Duration};

#[derive(Display)]
pub struct GrpcBlockSource {
    /// The gRPC client
    client: LedgerUpdatesClient,
    /// A logger object
    logger: Logger,
}

impl GrpcBlockSource {
    pub fn new(uri: &impl ConnectionUri, env: Arc<grpcio::Environment>, logger: Logger) -> Self {
        let logger = logger.new(o!("uri" => uri.to_string()));
        let channel =
            grpcio::ChannelBuilder::default_channel_builder(env).connect_to_uri(uri, &logger);
        let client = LedgerUpdatesClient::new(channel);
        Self { client, logger }
    }
}

impl BlockSource for GrpcBlockSource {
    type BlockStream = impl Stream<Item = StreamResult<BlockData>>;

    fn get_block_stream(&self, starting_height: u64) -> StreamResult<Self::BlockStream> {
        let logger = self.logger.clone();

        let mut req = SubscribeRequest::new();
        req.starting_height = starting_height;

        let opt = grpcio::CallOption::default().timeout(Duration::from_secs(10));

        let stream = self
            .client
            .subscribe_opt(&req, opt)
            .map_err(LedgerStreamingError::from)?;
        Ok(stream.map(move |res| map_subscribe_response(res, &logger)))
    }
}

fn map_subscribe_response(
    res: grpcio::Result<SubscribeResponse>,
    logger: &Logger,
) -> StreamResult<BlockData> {
    log::trace!(logger, "map_subscribe_response");
    let response = res.map_err(LedgerStreamingError::from)?;
    // TODO: Validate result against result_signature
    let archive_block = response.get_result().get_block();
    BlockData::try_from(archive_block).map_err(LedgerStreamingError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{setup_test_server, Responses};
    use futures::{executor::block_on, future::ready};
    use mc_common::logger::test_with_logger;
    use mc_transaction_core::{tx::TxOutMembershipElement, Block, BlockContents, BlockVersion};

    fn make_responses(num_responses: usize) -> Responses {
        let mut result: Responses = vec![];
        let mut parent: Option<Block> = None;
        for i in 0..num_responses {
            let contents = BlockContents::new(vec![], vec![]);
            let block = if i == 0 {
                Block::new_origin_block(&[])
            } else {
                let root_element = TxOutMembershipElement::default();
                Block::new_with_parent(
                    BlockVersion::MAX,
                    &parent.unwrap(),
                    &root_element,
                    &contents,
                )
            };
            parent = Some(block.clone());
            let block_data = BlockData::new(block, contents, None);
            let mut response = SubscribeResponse::new();
            response.mut_result().set_block((&block_data).into());
            result.push(Ok(response));
        }
        result
    }

    #[test_with_logger]
    fn basic(logger: Logger) {
        let responses = make_responses(3);
        let (_server, uri, env) = setup_test_server(responses, None, None);
        let source = GrpcBlockSource::new(&uri, env, logger.clone());

        let result_fut = source
            .get_block_stream(0)
            .expect("Failed to start block stream")
            .map(|resp| {
                let block_data = resp.expect("Error decoding block data");
                block_data.block().index
            })
            .collect();

        let result: Vec<u64> = block_on(result_fut);
        assert_eq!(result, &[0, 1, 2])
    }

    #[test_with_logger]
    fn propagates_errors(logger: Logger) {
        let mut responses = make_responses(2);
        responses.push(Err("meh".to_owned()));

        let (_server, uri, env) = setup_test_server(responses, None, None);
        let source = GrpcBlockSource::new(&uri, env, logger.clone());

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
