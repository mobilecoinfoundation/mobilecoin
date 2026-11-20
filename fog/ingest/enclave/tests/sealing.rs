// Copyright (c) 2018-2026 The MobileCoin Foundation

use mc_common::{
    logger::{test_with_logger, Logger},
    ResponderId,
};
use mc_fog_ingest_enclave::{IngestEnclave, IngestSgxEnclave, ENCLAVE_FILE};
use mc_fog_test_infra::get_enclave_path;
use mc_sgx_service::validate_sealed_blob_header;
use std::str::FromStr;

const OMAP_CAP: u64 = 256;

/// Test that an ingress private key sealed by one enclave instance can be
/// unsealed by another instance of the same enclave.
#[test_with_logger]
fn sealing_round_trip(logger: Logger) {
    let enclave_path = get_enclave_path(ENCLAVE_FILE);
    let responder_id = ResponderId::from_str("127.0.0.1:3040").unwrap();

    let enclave = IngestSgxEnclave::new(
        enclave_path.clone(),
        &responder_id,
        &None,
        OMAP_CAP,
        &logger,
    )
    .expect("could not initialize sealing enclave");
    let original_pubkey = enclave
        .get_ingress_pubkey()
        .expect("could not get original ingress public key");
    let (sealed_key, _) = enclave
        .get_sealed_ingress_private_key()
        .expect("could not seal ingress private key");
    validate_sealed_blob_header(&sealed_key)
        .expect("sealed ingress private key has unexpected header parameters");
    drop(enclave);

    let enclave = IngestSgxEnclave::new(
        enclave_path,
        &responder_id,
        &Some(sealed_key),
        OMAP_CAP,
        &logger,
    )
    .expect("could not initialize unsealing enclave");
    let restored_pubkey = enclave
        .get_ingress_pubkey()
        .expect("could not get restored ingress public key");

    assert_eq!(original_pubkey, restored_pubkey);
}
