// Copyright (c) 2018-2023 The MobileCoin Foundation
#![deny(missing_docs)]

//! A utility to load-test a fog-view server.

use grpcio::EnvBuilder;
use mc_common::logger::{create_root_logger, log, Logger};
use mc_fog_kex_rng::{NewFromKex, VersionedKexRng};
use mc_fog_uri::FogViewUri;
use mc_fog_view_connection::FogViewGrpcClient;
use mc_fog_view_protocol::FogViewConnection;
use mc_util_cli::ParserWithBuildInfo;
use mc_util_from_random::FromRandom;
use mc_util_grpc::GrpcRetryConfig;
use std::{
    fmt::Display,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, clap::Parser)]
#[clap(version)]
struct Config {
    /// View server URI
    #[clap(long, short, env = "MC_VIEW_URI")]
    pub view_uri: String,

    /// Number of worker threads
    #[clap(long, default_value = "1", env = "MC_NUM_WORKERS")]
    pub num_workers: usize,

    /// Number of search keys to include in each request
    #[clap(long, default_value = "1", env = "MC_NUM_SEARCH_KEYS")]
    pub num_search_keys: usize,

    /// Grpc retry config
    #[clap(flatten)]
    pub grpc_retry_config: GrpcRetryConfig,

    /// Max number of requests before the test ends (without ctrl-c)
    #[clap(long, default_value = "0", env = "MC_MAX_REQUESTS")]
    pub max_requests: u64,
}

/// Metrics that we aggregate for the load test
#[derive(Clone, Debug, Default)]
pub struct Counters {
    /// Number of requests made to fog view
    pub num_requests: u64,
    /// Number of errors resulting from those requests
    pub num_errors: u64,
    /// Total latency of these requests, in milliseconds
    pub total_millis_latency: u64,
}

impl Counters {
    fn avg_latency(&self) -> f64 {
        if self.num_requests == 0 {
            0f64
        } else {
            (self.total_millis_latency / self.num_requests) as f64 / 1000f64
        }
    }
}

impl Display for Counters {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "{{ {} requests, {} errors, {} avg latency (seconds) }}",
            self.num_requests,
            self.num_errors,
            self.avg_latency()
        )
    }
}

impl core::ops::Sub for Counters {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Self {
            num_requests: self.num_requests - other.num_requests,
            num_errors: self.num_errors - other.num_errors,
            total_millis_latency: self.total_millis_latency - other.total_millis_latency,
        }
    }
}

fn worker_thread(
    uri: String,
    grpc_retry_config: GrpcRetryConfig,
    num_search_keys: usize,
    counters: Arc<Mutex<Counters>>,
    stop_requested: Arc<AtomicBool>,
    logger: Logger,
) {
    let mut fog_view_client = build_fog_view_conn(&uri, grpc_retry_config, &logger);

    let resp = fog_view_client
        .request(0, 0, Default::default())
        .inspect_err(|_err| {
            stop_requested.store(true, Ordering::SeqCst);
        })
        .expect("request");
    let rng_record = &(resp.rng_records[0]);
    let private_key = FromRandom::from_random(&mut rand::thread_rng());
    let rng = VersionedKexRng::try_from_kex_pubkey(&rng_record.pubkey, &private_key).expect("kex");
    let search_keys = rng.take(num_search_keys).collect::<Vec<Vec<u8>>>();

    while !stop_requested.load(Ordering::SeqCst) {
        let start = Instant::now();
        let result = fog_view_client.request(0, 0, search_keys.clone());
        let duration = start.elapsed();

        let mut counters = counters.lock().unwrap();
        counters.num_requests += 1;
        counters.total_millis_latency += u64::try_from(duration.as_millis()).unwrap();
        if result.is_err() {
            counters.num_errors += 1;
        }
    }
}

fn main() {
    let config = Config::parse();
    let logger = create_root_logger();

    let stop_requested = Arc::new(AtomicBool::default());
    let r = stop_requested.clone();

    ctrlc::set_handler(move || {
        r.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let counters = Arc::new(Mutex::new(Counters::default()));
    for _ in 0..config.num_workers {
        let logger = logger.clone();
        let num_search_keys = config.num_search_keys;
        let counters = counters.clone();
        let stop_requested = stop_requested.clone();
        let uri = config.view_uri.clone();
        let retry_config = config.grpc_retry_config;

        thread::spawn(move || {
            worker_thread(
                uri,
                retry_config,
                num_search_keys,
                counters,
                stop_requested,
                logger,
            )
        });
    }

    let start_test = Instant::now();

    let mut last_counters = Counters::default();
    let mut last_display = Instant::now();
    while !stop_requested.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));

        let current_counters = counters.lock().unwrap().clone();
        if current_counters.num_requests > last_counters.num_requests {
            let now = Instant::now();
            let duration = now.duration_since(last_display);

            let diff = current_counters.clone() - last_counters.clone();
            let requests_per_second = diff.num_requests as f64 / duration.as_secs_f64();
            let errors_per_second = diff.num_errors as f64 / duration.as_secs_f64();

            println!(
                "{{ requests per second: {}, errors per second: {}, avg latency (seconds) {} }}",
                requests_per_second,
                errors_per_second,
                diff.avg_latency()
            );
            last_display = now;
            last_counters = current_counters.clone();
        }

        // terminate test if we have exceeded maximum number of requests to perform, and
        // this max is not zero.
        if config.max_requests != 0 && current_counters.num_requests >= config.max_requests {
            stop_requested.store(true, Ordering::SeqCst);
        }
    }

    let total_duration = Instant::now().duration_since(start_test);

    println!(
        "Total test time (seconds): {}",
        total_duration.as_secs_f64()
    );
    println!("{}", counters.lock().unwrap());
    println!("Config: {config:?}");
}

fn build_fog_view_conn(
    uri: &str,
    grpc_retry_config: GrpcRetryConfig,
    logger: &Logger,
) -> FogViewGrpcClient {
    let grpc_env = Arc::new(
        EnvBuilder::new()
            .name_prefix("view-grpc".to_owned())
            .build(),
    );

    let identity = mc_fog_view_enclave_measurement::mr_signer_identity(None);

    log::debug!(logger, "Fog view attestation identity: {:?}", identity);

    let client_uri = FogViewUri::from_str(uri)
        .unwrap_or_else(|e| panic!("Could not parse client uri: {uri}: {e:?}"));

    // TODO: Supply chain-id to the load-test binary?
    FogViewGrpcClient::new(
        String::default(),
        client_uri,
        grpc_retry_config,
        [identity],
        grpc_env,
        logger.clone(),
    )
}
