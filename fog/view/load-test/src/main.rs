// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A utility to load-test a fog-view server.

use grpcio::EnvBuilder;
use mc_account_keys::AccountKey;
use mc_attest_core::{Verifier, DEBUG_ENCLAVE};
use mc_common::logger::{create_root_logger, log, Logger};
use mc_fog_kex_rng::{NewFromKex, VersionedKexRng};
use mc_fog_uri::FogViewUri;
use mc_fog_view_connection::FogViewGrpcClient;
use mc_fog_view_protocol::FogViewConnection;
use std::{
    path::PathBuf,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Config {
    /// Path to root identity file to use
    /// Note: This contains the fog-url which is the same as the report-server
    /// uri
    #[structopt(long)]
    pub keyfile: PathBuf,

    /// View server URI
    #[structopt(long)]
    pub view_uri: String,

    /// Number of worker threads
    #[structopt(long, default_value = "1")]
    pub num_workers: usize,

    /// Number of search keys to include in request
    #[structopt(long, default_value = "100")]
    pub num_search_keys: usize,
}

fn worker_thread(
    uri: String,
    account_key: AccountKey,
    num_search_keys: usize,
    num_reqs: Arc<AtomicU64>,
    logger: Logger,
) {
    let mut fog_view_client = build_fog_view_conn(&uri, &logger);

    let resp = fog_view_client
        .request(0, 0, Default::default())
        .expect("request");
    let rng_record = &(resp.rng_records[0]);
    let rng = VersionedKexRng::try_from_kex_pubkey(
        &rng_record.pubkey,
        &account_key.default_subaddress_view_private(),
    )
    .expect("kex");
    let search_keys = rng.take(num_search_keys).collect::<Vec<Vec<u8>>>();

    loop {
        let _resp = fog_view_client
            .request(0, 0, search_keys.clone())
            .expect("request");
        num_reqs.fetch_add(1, Ordering::SeqCst);
    }
}

fn main() {
    let config = Config::from_args();
    let logger = create_root_logger();

    let root_identity =
        mc_util_keyfile::read_keyfile(config.keyfile).expect("Could not read private key file");
    let account_key = AccountKey::from(&root_identity);

    let num_reqs = Arc::new(AtomicU64::new(0));
    for _ in 0..config.num_workers {
        let logger = logger.clone();
        let account_key = account_key.clone();
        let num_search_keys = config.num_search_keys;
        let num_reqs = num_reqs.clone();
        let uri = config.view_uri.clone();

        thread::spawn(move || worker_thread(uri, account_key, num_search_keys, num_reqs, logger));
    }

    loop {
        let num_reqs_before = num_reqs.load(Ordering::SeqCst);
        thread::sleep(Duration::from_secs(1));
        let num_reqs_after = num_reqs.load(Ordering::SeqCst);

        println!("requests per second: {}", num_reqs_after - num_reqs_before);
    }
}

fn build_fog_view_conn(uri: &str, logger: &Logger) -> FogViewGrpcClient {
    let grpc_env = Arc::new(
        EnvBuilder::new()
            .name_prefix("view-grpc".to_owned())
            .build(),
    );

    let verifier = {
        let mr_signer_verifier = mc_fog_view_enclave_measurement::get_mr_signer_verifier(None);

        let mut verifier = Verifier::default();
        verifier.mr_signer(mr_signer_verifier).debug(DEBUG_ENCLAVE);
        verifier
    };

    log::debug!(logger, "Fog view attestation verifier: {:?}", verifier);

    let client_uri = FogViewUri::from_str(uri)
        .unwrap_or_else(|e| panic!("Could not parse client uri: {}: {:?}", uri, e));

    FogViewGrpcClient::new(client_uri, verifier, grpc_env, logger.clone())
}
