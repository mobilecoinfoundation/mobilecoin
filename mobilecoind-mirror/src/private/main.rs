// Copyright (c) 2018-2020 MobileCoin Inc.

//! The private side of mobilecoind-mirror.
//! This program forms outgoing connections to both a mobilecoind instance, as well as a public
//! mobilecoind-mirror instance. It then proceeds to poll the public side of the mirror for
//! requests which it then forwards to mobilecoind. When a response is received it is then
//! forwarded back to the mirror.

use grpcio::{ChannelBuilder, ChannelCredentialsBuilder, RpcStatus, RpcStatusCode};
use mc_common::logger::{create_app_logger, log, o, Logger};
use mc_mobilecoind_api::mobilecoind_api_grpc::MobilecoindApiClient;
use mc_mobilecoind_mirror::{
    mobilecoind_mirror_api::{PollRequest, QueryRequest, QueryResponse},
    mobilecoind_mirror_api_grpc::MobilecoindMirrorApiClient,
    uri::MobilecoindMirrorUri,
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use std::{collections::HashMap, str::FromStr, sync::Arc, thread::sleep, time::Duration};
use structopt::StructOpt;

/// Command line config
#[derive(Clone, Debug, StructOpt)]
#[structopt(
    name = "mobilecoind-mirror-private",
    about = "The private side of mobilecoind-mirror, receiving requests from the public side and forwarding them to mobilecoind"
)]
pub struct Config {
    /// MobileCoinD URI.
    #[structopt(long, default_value = "127.0.0.1:4444")]
    pub mobilecoind_host: String,

    /// Use SSL when connecting to mobilecoind.
    #[structopt(long)]
    pub mobilecoind_ssl: bool,

    /// URI for the public side of the mirror.
    #[structopt(long)]
    pub mirror_public_uri: MobilecoindMirrorUri,

    /// How many seconds to wait between polling.
    #[structopt(long, default_value = "1", parse(try_from_str=parse_duration_in_seconds))]
    pub poll_interval: Duration,
}

fn main() {
    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();

    let config = Config::from_args();

    let (logger, _global_logger_guard) = create_app_logger(o!());
    log::info!(
        logger,
        "Starting mobilecoind mirror private forwarder on {}, connecting to mobilecoind {}",
        config.mirror_public_uri,
        config.mobilecoind_host
    );

    // Set up the gRPC connection to the mobilecoind client
    let mobilecoind_api_client = {
        let env = Arc::new(grpcio::EnvBuilder::new().build());
        let ch_builder = ChannelBuilder::new(env)
            .max_receive_message_len(std::i32::MAX)
            .max_send_message_len(std::i32::MAX);

        let ch = if config.mobilecoind_ssl {
            let creds = ChannelCredentialsBuilder::new().build();
            ch_builder.secure_connect(&config.mobilecoind_host, creds)
        } else {
            ch_builder.connect(&config.mobilecoind_host)
        };

        MobilecoindApiClient::new(ch)
    };

    // Set up the gRPC connection to the public side of the mirror.
    let mirror_api_client = {
        let env = Arc::new(grpcio::EnvBuilder::new().build());
        let ch = ChannelBuilder::new(env)
            .max_receive_message_len(std::i32::MAX)
            .max_send_message_len(std::i32::MAX)
            .connect_to_uri(&config.mirror_public_uri, &logger);

        MobilecoindMirrorApiClient::new(ch)
    };

    // Main polling loop.
    log::debug!(logger, "Entering main loop");

    let mut pending_responses: HashMap<String, QueryResponse> = HashMap::new();

    loop {
        // Communicate with the public side of the mirror.
        let mut request = PollRequest::new();
        request.set_query_responses(pending_responses.clone());

        log::debug!(
            logger,
            "Calling poll with {} queued responses",
            pending_responses.len()
        );
        match mirror_api_client.poll(&request) {
            Ok(response) => {
                log::debug!(
                    logger,
                    "Poll succeeded, got back {} requests",
                    response.query_requests.len()
                );

                // Clear pending responses since we successfully delivered them to the other side.
                pending_responses.clear();

                // Process requests.
                for (query_id, query_request) in response.query_requests.iter() {
                    let query_logger = logger.new(o!("query_id" => query_id.clone()));

                    pending_responses.insert(
                        query_id.clone(),
                        process_request(&mobilecoind_api_client, query_request, &query_logger)
                            .unwrap_or_else(|err| {
                                log::error!(query_logger, "process_request failed: {:?}", err);

                                let mut err_query_response = QueryResponse::new();
                                err_query_response.set_error(err.to_string());
                                err_query_response
                            }),
                    );
                }
            }

            Err(err) => {
                log::error!(
                    logger,
                    "Polling the public side of the mirror failed: {:?}",
                    err
                );
            }
        }

        sleep(config.poll_interval);
    }
}

fn process_request(
    mobilecoind_api_client: &MobilecoindApiClient,
    query_request: &QueryRequest,
    logger: &Logger,
) -> grpcio::Result<QueryResponse> {
    let mut mirror_response = QueryResponse::new();

    // GetProcessedBlock
    if query_request.has_get_processed_block() {
        let mirror_request = query_request.get_get_processed_block();
        let mut mobilecoind_request = mc_mobilecoind_api::GetProcessedBlockRequest::new();
        // TODO monitor!
        mobilecoind_request.set_block(mirror_request.block);

        log::info!(
            logger,
            "get_processed_block(TODO, {})",
            mirror_request.block
        );
        let mobilecoind_response =
            mobilecoind_api_client.get_processed_block(&mobilecoind_request)?;

        mirror_response.set_get_processed_block(mobilecoind_response);
        return Ok(mirror_response);
    }

    // GetBlockRequest
    if query_request.has_get_block() {
        let mirror_request = query_request.get_get_block();
        let mut mobilecoind_request = mc_mobilecoind_api::GetBlockRequest::new();
        mobilecoind_request.set_block(mirror_request.block);

        log::info!(logger, "get_block({})", mirror_request.block);
        let mobilecoind_response = mobilecoind_api_client.get_block(&mobilecoind_request)?;

        mirror_response.set_get_block(mobilecoind_response);
        return Ok(mirror_response);
    }

    // Unknown response.
    Err(grpcio::Error::RpcFailure(RpcStatus::new(
        RpcStatusCode::INTERNAL,
        Some("Unsupported request".into()),
    )))
}

fn parse_duration_in_seconds(src: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_secs(u64::from_str(src)?))
}
