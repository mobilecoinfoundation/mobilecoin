// Copyright (c) 2018-2022 The MobileCoin Foundation

use aes_gcm::Aes256Gcm;
use mc_attest_ake::{AuthResponseInput, ClientInitiate, Start, Transition};
use mc_attest_api::attest::{AuthMessage, Message};
use mc_attest_net::{Client, RaClient};
use mc_common::{
    logger::{test_with_logger, Logger},
    ResponderId,
};
use mc_consensus_enclave::{ConsensusEnclave, ConsensusServiceSgxEnclave, ENCLAVE_FILE};
use mc_consensus_enclave_api::{BlockchainConfig, FeeMap};
use mc_crypto_keys::X25519;
use mc_crypto_rand::McRng;
use mc_fog_test_infra::get_enclave_path;
use mc_ledger_db::{
    test_utils::{create_ledger, create_transaction, initialize_ledger},
    Ledger,
};
use mc_sgx_report_cache_untrusted::ReportCache;
use mc_transaction_core::{AccountKey, BlockVersion};
use mc_util_metrics::IntGauge;
use mc_util_serial::encode;
use sha2::Sha512;
use std::str::FromStr;

lazy_static::lazy_static! {
    pub static ref DUMMY_INT_GAUGE: IntGauge = IntGauge::new("foo".to_string(), "bar".to_string()).unwrap();
}

/// Test that we can exercise client_tx_propose and that it passes and fails
/// as expected.
#[test_with_logger]
fn consensus_enclave_client_tx_propose(logger: Logger) {
    let mut rng = McRng::default();

    let responder_id = ResponderId::from_str("127.0.0.1:3000").unwrap();
    let block_version = BlockVersion::MAX;
    let fee_map = FeeMap::default();

    let blockchain_config = BlockchainConfig {
        block_version,
        fee_map,
        ..Default::default()
    };

    let (enclave, _, _) = ConsensusServiceSgxEnclave::new(
        get_enclave_path(ENCLAVE_FILE),
        &responder_id,
        &responder_id,
        &None,
        blockchain_config,
    );

    // Update enclave report cache, using SIM or HW-mode RA client as appropriate
    let ias_spid = Default::default();
    let ias_api_key = core::str::from_utf8(&[0u8; 64]).unwrap();
    let ias_client = Client::new(ias_api_key).expect("Could not create IAS client");

    let report_cache = ReportCache::new(
        enclave.clone(),
        ias_client,
        ias_spid,
        &DUMMY_INT_GAUGE,
        logger,
    );
    report_cache.start_report_cache().unwrap();
    report_cache.update_enclave_report_cache().unwrap();

    // First, create an encrypted connection from a client
    let initiator = Start::new(responder_id.to_string());
    let init_input = ClientInitiate::<X25519, Aes256Gcm, Sha512>::default();
    let (initiator, auth_request_output) = initiator.try_next(&mut rng, init_input).unwrap();

    let auth_request_msg = AuthMessage::from(auth_request_output);
    let (auth_response_msg, _client_session) =
        enclave.client_accept(auth_request_msg.into()).unwrap();
    let auth_response_msg = AuthMessage::from(auth_response_msg);

    // Now the client should have a working cipher state
    let verifier = Default::default();
    let auth_response_event = AuthResponseInput::new(auth_response_msg.into(), verifier);
    let (mut initiator, _verification_report) =
        initiator.try_next(&mut rng, auth_response_event).unwrap();

    // Create a valid test transaction.
    let sender = AccountKey::random(&mut rng);
    let recipient = AccountKey::random(&mut rng);

    let mut ledger = create_ledger();
    let n_blocks = 3;
    initialize_ledger(block_version, &mut ledger, n_blocks, &sender, &mut rng);

    // Choose a TxOut to spend. Only the TxOut in the last block is unspent.
    let block_contents = ledger.get_block_contents(n_blocks - 1).unwrap();
    let tx_out = block_contents.outputs[0].clone();

    let tx = create_transaction(
        block_version,
        &mut ledger,
        &tx_out,
        &sender,
        &recipient.default_subaddress(),
        n_blocks + 1,
        &mut rng,
    );

    // Try to propose the Tx
    let req = tx;

    let ciphertext = initiator.encrypt(&[], &encode(&req)).unwrap();

    let mut msg = Message::new();
    msg.set_channel_id(Vec::from(initiator.binding()));
    msg.set_data(ciphertext);

    enclave
        .client_tx_propose(msg.into())
        .expect("unexpected failure to propose tx");

    // Now, let's screw with the tx such that it should fail deserialization
    let bad_req_bytes = [255u8; 8];

    let tx_ciphertext = initiator.encrypt(&[], &bad_req_bytes).unwrap();

    let mut msg = Message::new();
    msg.set_channel_id(Vec::from(initiator.binding()));
    msg.set_data(tx_ciphertext);

    let result = enclave.client_tx_propose(msg.into());
    assert!(result.is_err(), "unexpected success with bad serialized Tx");
}
