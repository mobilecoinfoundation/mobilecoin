// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! Entrypoint for the MobileCoin server.

use mc_attest_net::{Client, RaClient};
use mc_attest_verifier::DEBUG_ENCLAVE;
use mc_common::{
    logger::{create_app_logger, log, o},
    time::SystemTimeProvider,
};
use mc_consensus_enclave::{BlockchainConfig, ConsensusServiceSgxEnclave, ENCLAVE_FILE};
use mc_consensus_service::{
    consensus_service::{ConsensusService, ConsensusServiceError},
    mint_tx_manager::MintTxManagerImpl,
    tx_manager::TxManagerImpl,
    validators::DefaultTxManagerUntrustedInterfaces,
};
use mc_consensus_service_config::Config;
use mc_ledger_db::LedgerDB;
use mc_util_cli::ParserWithBuildInfo;
use std::{
    env,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

fn main() -> Result<(), ConsensusServiceError> {
    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();

    let config = Config::parse();
    let local_node_id = config.node_id();
    let fee_map = config.tokens().fee_map().expect("Could not parse fee map");
    let governors_map = config
        .tokens()
        .token_id_to_governors()
        .expect("Could not parse governors map");

    let (logger, _global_logger_guard) = create_app_logger(o!(
        "mc.local_node_id" => local_node_id.responder_id.to_string(),
    ));

    let _tracer = mc_util_telemetry::setup_default_tracer_with_tags(
        env!("CARGO_PKG_NAME"),
        &[("local_node_id", local_node_id.responder_id.to_string())],
    )
    .expect("Failed setting telemetry tracer");

    // load the sealed block signing key fron storage
    let cached_key = match File::open(&config.sealed_block_signing_key) {
        Ok(mut file) => {
            let mut contents = String::new();
            match file.read_to_string(&mut contents) {
                Ok(_) => Some(contents.as_bytes().to_vec()),
                Err(_) => None,
            }
        }
        Err(_) => None,
    };

    mc_common::sentry::configure_scope(|scope| {
        scope.set_tag("local_node_id", local_node_id.responder_id.to_string());
    });

    let blockchain_config = BlockchainConfig {
        fee_map: fee_map.clone(),
        governors_map: governors_map.clone(),
        governors_signature: config.tokens().governors_signature,
        block_version: config.block_version,
    };

    let enclave_path = env::current_exe()
        .expect("Could not get the path of our executable")
        .with_file_name(ENCLAVE_FILE);
    let (enclave, sealed_key, features) = ConsensusServiceSgxEnclave::new(
        enclave_path,
        &config.peer_responder_id,
        &config.client_responder_id,
        &cached_key,
        blockchain_config,
    );

    log::info!(logger, "Enclave target features: {}", features.join(", "));
    log::info!(logger, "Configured minimum fees: {:?}", fee_map);

    // write the sealed block signing key
    let mut sealed_key_file =
        File::create(&config.sealed_block_signing_key).expect("Failed to open sealed key file");
    sealed_key_file
        .write_all(&sealed_key)
        .expect("Failed to write sealed key bytes");

    setup_ledger_dir(&config.origin_block_path, &config.ledger_path);

    let local_ledger = LedgerDB::open(&config.ledger_path).expect("Failed creating LedgerDB");

    let ias_client = Client::new(&config.ias_api_key).expect("Could not create IAS client");

    if DEBUG_ENCLAVE {
        log::error!(
            logger,
            "Enclave will be started in debug mode, there is no privacy"
        );
    } else {
        log::debug!(logger, "Enclave will be started in production mode");
    }

    let tx_manager = TxManagerImpl::new(
        enclave.clone(),
        DefaultTxManagerUntrustedInterfaces::new(local_ledger.clone()),
        logger.clone(),
    );

    let mint_tx_manager = MintTxManagerImpl::new(
        local_ledger.clone(),
        config.block_version,
        governors_map,
        logger.clone(),
    );

    let mut consensus_service = ConsensusService::new(
        config,
        enclave,
        local_ledger,
        ias_client,
        Arc::new(tx_manager),
        Arc::new(mint_tx_manager),
        Arc::new(SystemTimeProvider::default()),
        logger.clone(),
    );
    consensus_service
        .start()
        .expect("Failed starting consensus service :-(");

    log::info!(logger, "Listening...");

    consensus_service.wait_for_all_threads()?;

    // Should never get here since our threads are not expected to die
    panic!("Oh oh, our threads died");
}

fn setup_ledger_dir(config_origin_path: &Option<PathBuf>, ledger_path: &Path) {
    if let Some(origin_block_path) = config_origin_path.clone() {
        // Copy origin block to ledger_db path if there are not already contents in
        // ledger_db. If ledger_path does not exist, create the dir.
        std::fs::create_dir_all(ledger_path).expect("Could not create ledger directory");
        let mut options = fs_extra::dir::CopyOptions::new();
        options.skip_exist = true;
        options.copy_inside = true;
        let mut data_file_path = origin_block_path;

        // Copy the data.mdb file from the origin directory to the ledger
        data_file_path.push("data.mdb");
        fs_extra::copy_items(&[data_file_path], ledger_path, &options)
            .expect("Could not copy origin block");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        io::{Read, Write},
    };
    use tempdir::TempDir;

    #[test]
    #[should_panic]
    fn test_missing_origin_dir() {
        // If a origin directory is provided but doesn't exist we should panic
        let origin_block_path = TempDir::new("origin").unwrap();
        let ledger_path = TempDir::new("ledger").unwrap();
        setup_ledger_dir(
            &Some(origin_block_path.path().to_path_buf()),
            ledger_path.path(),
        );
    }

    #[test]
    fn test_empty_ledger_dir() {
        // If the ledger directory exists and is empty, the origin files should be
        // copied
        let origin_block_path = TempDir::new("origin").unwrap();

        // This will create the ledger path
        let ledger_path = TempDir::new("ledger").unwrap();
        assert!(ledger_path.path().exists());

        let data_path = origin_block_path.path().join("data.mdb");
        File::create(data_path).unwrap();

        setup_ledger_dir(
            &Some(origin_block_path.path().to_path_buf()),
            ledger_path.path(),
        );

        let new_data_path = ledger_path.path().join("data.mdb");
        assert!(new_data_path.exists());
    }

    #[test]
    fn test_new_ledger_dir() {
        // If the ledger directory does not exist, it should be created and the origin
        // files copied
        let origin_block_path = TempDir::new("origin").unwrap();
        let ledger_path = TempDir::new("ledger").unwrap();

        // TempDir will create the ledger path, remove it to make sure it gets created
        std::fs::remove_dir(&ledger_path).unwrap();
        assert!(!ledger_path.path().exists());

        let data_path = origin_block_path.path().join("data.mdb");
        File::create(data_path).unwrap();

        setup_ledger_dir(
            &Some(origin_block_path.path().to_path_buf()),
            ledger_path.path(),
        );

        let new_data_path = ledger_path.path().join("data.mdb");
        assert!(new_data_path.exists());
    }

    #[test]
    fn test_existing_ledger_data() {
        // If there is already ledger data it should not be overwritten
        let origin_block_path = TempDir::new("origin").unwrap();
        let ledger_path = TempDir::new("ledger").unwrap();

        // Create empty files in origin
        let data_path = origin_block_path.path().join("data.mdb");
        {
            File::create(data_path).unwrap();
        }

        // Create files in ledger with something in them
        let ledger_data_path = ledger_path.path().join("data.mdb");
        {
            let mut data_file = File::create(&ledger_data_path).unwrap();
            write!(data_file, "data").unwrap();
        }

        setup_ledger_dir(
            &Some(origin_block_path.path().to_path_buf()),
            ledger_path.path(),
        );

        let mut data_file = File::open(&ledger_data_path).unwrap();
        let mut data_contents = String::new();
        data_file.read_to_string(&mut data_contents).unwrap();
        assert_eq!(data_contents, "data");
    }
}
