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
    mobilecoind_mirror_api_grpc::MobilecoindMirrorClient,
    uri::MobilecoindMirrorUri,
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use std::{collections::HashMap, str::FromStr, sync::Arc, thread::sleep, time::Duration};
use structopt::StructOpt;

/// A wrapper to ease monitor id parsing from a hex string when using `StructOpt`.
#[derive(Clone, Debug)]
pub struct MonitorId(pub Vec<u8>);
impl FromStr for MonitorId {
    type Err = String;
    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let bytes =
            hex::decode(src).map_err(|err| format!("Error decoding monitor id: {:?}", err))?;
        if bytes.len() != 32 {
            return Err("monitor id needs to be exactly 32 bytes".into());
        }
        Ok(Self(bytes))
    }
}

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

    /// How many milliseconds to wait between polling.
    #[structopt(long, default_value = "100", parse(try_from_str=parse_duration_in_milliseconds))]
    pub poll_interval: Duration,

    /// Monitor id to operate with. If not provided, mobilecoind will be queried and if it has only
    /// one monitor id that one would be automatically chosen.
    #[structopt(long)]
    pub monitor_id: Option<MonitorId>,
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

        MobilecoindMirrorClient::new(ch)
    };

    // Figure out which monitor id we are working with.
    let monitor_id = config.monitor_id.map(|m| m.0).unwrap_or_else(|| {
        let response = mobilecoind_api_client.get_monitor_list(&mc_mobilecoind_api::Empty::new()).expect("Failed querying mobilecoind for list of configured monitors");
        match response.monitor_id_list.len() {
            0 => panic!("Mobilecoind has no monitors configured"),
            1 => response.monitor_id_list[0].to_vec(),
            _ => {
                let monitor_ids = response.get_monitor_id_list().iter().map(hex::encode).collect::<Vec<_>>();
                panic!("Mobilecoind has more than one configured monitor, use --monitor-id to select which one to use. The following monitor ids were reported: {:?}", monitor_ids);
            }
    }});
    log::info!(logger, "Monitor id: {}", hex::encode(&monitor_id));

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
                        process_request(
                            &mobilecoind_api_client,
                            &monitor_id,
                            query_request,
                            &query_logger,
                        )
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
    monitor_id: &[u8],
    query_request: &QueryRequest,
    logger: &Logger,
) -> grpcio::Result<QueryResponse> {
    let mut mirror_response = QueryResponse::new();

    // GetProcessedBlock
    if query_request.has_get_processed_block() {
        let mirror_request = query_request.get_get_processed_block();
        let mut mobilecoind_request = mc_mobilecoind_api::GetProcessedBlockRequest::new();
        mobilecoind_request.set_monitor_id(monitor_id.to_vec());
        mobilecoind_request.set_block(mirror_request.block);

        log::debug!(
            logger,
            "Incoming get_processed_block({}, {}), forwarding to mobilecoind",
            hex::encode(monitor_id),
            mirror_request.block
        );
        let mobilecoind_response =
            mobilecoind_api_client.get_processed_block(&mobilecoind_request)?;
        log::info!(
            logger,
            "get_processed_block({}, {}) succeeded",
            hex::encode(monitor_id),
            mirror_request.block,
        );

        mirror_response.set_get_processed_block(mobilecoind_response);
        return Ok(mirror_response);
    }

    // GetBlockRequest
    if query_request.has_get_block() {
        let mirror_request = query_request.get_get_block();
        let mut mobilecoind_request = mc_mobilecoind_api::GetBlockRequest::new();
        mobilecoind_request.set_block(mirror_request.block);

        log::debug!(
            logger,
            "Incoming get_block({}), forwarding to mobilecoind",
            mirror_request.block
        );
        let mobilecoind_response = mobilecoind_api_client.get_block(&mobilecoind_request)?;
        log::info!(logger, "get_block({}) succeeded", mirror_request.block,);

        mirror_response.set_get_block(mobilecoind_response);
        return Ok(mirror_response);
    }

    // Unknown response.
    Err(grpcio::Error::RpcFailure(RpcStatus::new(
        RpcStatusCode::INTERNAL,
        Some("Unsupported request".into()),
    )))
}

fn parse_duration_in_milliseconds(src: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_millis(u64::from_str(src)?))
}
