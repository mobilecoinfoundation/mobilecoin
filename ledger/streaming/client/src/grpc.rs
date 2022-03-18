// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use futures::{Stream, StreamExt};
use mc_common::logger::{log, o, Logger};
use mc_crypto_keys::Ed25519Public;
use mc_ledger_streaming_api::{
    parse_subscribe_response,
    streaming_blocks::{SubscribeRequest, SubscribeResponse},
    streaming_blocks_grpc::LedgerUpdatesClient,
    BlockStream, BlockStreamComponents, Result,
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::ConnectionUri;
use std::{sync::Arc, time::Duration};

#[derive(Display)]
pub struct GrpcBlockSource {
    /// The gRPC client
    client: LedgerUpdatesClient,
    /// The public key of the consensus node we're streaming from.
    public_key: Arc<Ed25519Public>,
    /// A logger object
    logger: Logger,
}

impl GrpcBlockSource {
    pub fn new(
        uri: &impl ConnectionUri,
        env: Arc<grpcio::Environment>,
        public_key: Ed25519Public,
        logger: Logger,
    ) -> Self {
        let logger = logger.new(o!("uri" => uri.to_string()));
        let channel =
            grpcio::ChannelBuilder::default_channel_builder(env).connect_to_uri(uri, &logger);
        let client = LedgerUpdatesClient::new(channel);
        Self {
            client,
            public_key: Arc::new(public_key),
            logger,
        }
    }
}

impl BlockStream for GrpcBlockSource {
    type Stream = impl Stream<Item = Result<BlockStreamComponents>>;

    fn get_block_stream(&self, starting_height: u64) -> Result<Self::Stream> {
        // Clone members to satisfy 'static lifetime requirement.
        let logger = self.logger.clone();
        let public_key = self.public_key.clone();

        // Set up request.
        let mut req = SubscribeRequest::new();
        req.starting_height = starting_height;

        let opt = grpcio::CallOption::default().timeout(Duration::from_secs(10));

        let stream = self.client.subscribe_opt(&req, opt)?;
        Ok(stream.map(move |res| map_subscribe_response(res, &public_key, &logger)))
    }
}

fn map_subscribe_response(
    response: grpcio::Result<SubscribeResponse>,
    public_key: &Ed25519Public,
    logger: &Logger,
) -> Result<BlockStreamComponents> {
    log::trace!(logger, "map_subscribe_response");
    let response = response?;
    parse_subscribe_response(&response, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::setup_test_server;
    use futures::{executor::block_on, future::ready};
    use mc_common::logger::test_with_logger;
    use mc_crypto_keys::Ed25519Pair;
    use mc_ledger_streaming_api::{
        make_subscribe_response,
        test_utils::{make_quorum_set, Responses},
        Error,
    };
    use mc_transaction_core::{
        tx::TxOutMembershipElement, Block, BlockContents, BlockData, BlockVersion,
    };
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    fn make_responses(num_responses: usize, signer: &Ed25519Pair) -> Responses {
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
            let quorum_set = Some(make_quorum_set());
            let components = BlockStreamComponents {
                block_data,
                quorum_set,
                verification_report: None,
            };
            result.push(make_subscribe_response(&components, signer).into());
        }
        result
    }

    #[test_with_logger]
    fn basic(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer = Ed25519Pair::from_random(&mut rng);
        let responses = make_responses(3, &signer);
        let (_server, uri, env) = setup_test_server(responses, None, None);
        let source = GrpcBlockSource::new(&uri, env, signer.public_key(), logger.clone());

        let result_fut = source
            .get_block_stream(0)
            .expect("Failed to start block stream")
            .map(|result| {
                let data = result.expect("Error decoding block data");
                data.block_data.block().index
            })
            .collect();

        let result: Vec<u64> = block_on(result_fut);
        assert_eq!(result, &[0, 1, 2])
    }

    #[test_with_logger]
    fn propagates_errors(logger: Logger) {
        let mut csprng = Hc128Rng::seed_from_u64(0);
        let signer = Ed25519Pair::from_random(&mut csprng);

        let mut responses = make_responses(2, &signer);
        responses.push(Err(Error::Grpc("meh".to_owned())).into());

        let (_server, uri, env) = setup_test_server(responses, None, None);
        let source = GrpcBlockSource::new(&uri, env, signer.public_key(), logger.clone());

        let mut got_error = false;
        let result_fut = source
            .get_block_stream(0)
            .expect("Failed to start block stream")
            .filter_map(|resp| match resp {
                Ok(data) => ready(Some(data.block_data.block().index)),
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
