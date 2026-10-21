// Copyright (c) 2018-2026 The MobileCoin Foundation

use aes_gcm::Aes256Gcm;
use mc_attest_ake::{AuthResponseInput, ClientInitiate, Ready, Start, Transition};
use mc_attest_api::attest;
use mc_attest_enclave_api::{ClientSession, EnclaveMessage, Error as AttestEnclaveError};
use mc_common::{
    logger::{test_with_logger, Logger},
    ResponderId,
};
use mc_crypto_keys::X25519;
use mc_fog_test_infra::get_enclave_path;
use mc_fog_types::{
    common::BlockRange,
    view::{
        FixedTxOutSearchResult, MultiViewStoreQueryResponse, MultiViewStoreQueryResponseStatus,
        QueryRequest, QueryRequestAAD, QueryResponse, TxOutSearchResultCode,
    },
    ETxOutRecord,
};
use mc_fog_view_enclave::{SgxViewEnclave, ENCLAVE_FILE};
use mc_fog_view_enclave_api::{Error as ViewEnclaveError, UntrustedQueryResponse, ViewEnclaveApi};
use mc_rand::CryptoRng;
use mc_sgx_report_cache_untrusted::ReportCache;
use mc_util_metrics::IntGauge;
use mc_util_test_helper::{RngType, SeedableRng};
use sha2::Sha512;
use std::{str::FromStr, sync::LazyLock};

static TEST_ATTESTATION_EVIDENCE_TIMESTAMP: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::new(
        "view_response_routing_test_attestation_evidence_timestamp",
        "Test attestation evidence timestamp",
    )
    .unwrap()
});

fn connect_client<R: CryptoRng>(
    enclave: &SgxViewEnclave,
    responder_id: &ResponderId,
    rng: &mut R,
) -> (Ready<Aes256Gcm>, ClientSession) {
    let initiator = Start::new(responder_id.to_string());
    let init_input = ClientInitiate::<X25519, Aes256Gcm, Sha512>::default();
    let (initiator, auth_request_output) = initiator
        .try_next(rng, init_input)
        .expect("Could not encrypt auth message.");

    let auth_message = attest::AuthMessage::from(auth_request_output);
    let (client_auth_response, client_session) = enclave
        .client_accept(auth_message.into())
        .expect("Could not connect a client to the view enclave.");

    let auth_message = attest::AuthMessage::from(client_auth_response);
    let identity = mc_fog_view_enclave_measurement::mr_signer_identity(None);
    let auth_response_event = AuthResponseInput::new(auth_message.into(), [identity], None);
    let (noise_connection, _verification_report) = initiator
        .try_next(rng, auth_response_event)
        .expect("Could not complete the client Noise session.");

    (noise_connection, client_session)
}

#[test_with_logger]
fn rejects_redirected_view_response(logger: Logger) {
    let responder_id = ResponderId::from_str("view-response-routing.test:3223").unwrap();
    let enclave = SgxViewEnclave::new(
        get_enclave_path(ENCLAVE_FILE),
        responder_id.clone(),
        256,
        logger.clone(),
    );
    let mut rng = RngType::from_seed([7; 32]);

    ReportCache::new(
        enclave.clone(),
        &TEST_ATTESTATION_EVIDENCE_TIMESTAMP,
        logger,
    )
    .update_enclave_report_cache()
    .expect("Could not cache attestation evidence.");

    // Use the same enclave as router and store, with an authenticated backend
    // session, so collation receives a genuine, nonempty shard response.
    let backend_request = enclave
        .view_store_init(responder_id.clone())
        .expect("Could not initialize the view store session.");
    let (backend_response, _frontend_session) = enclave
        .frontend_accept(backend_request)
        .expect("Could not accept the view store session.");
    enclave
        .view_store_connect(responder_id.clone(), backend_response)
        .expect("Could not connect the view store session.");

    let record = ETxOutRecord {
        search_key: vec![7; 16],
        payload: vec![9; 232],
    };
    enclave
        .add_records(vec![record.clone()])
        .expect("Could not add the view record.");

    let (mut victim_noise, victim_session) = connect_client(&enclave, &responder_id, &mut rng);
    let (_attacker_noise, attacker_session) = connect_client(&enclave, &responder_id, &mut rng);
    assert_ne!(victim_session, attacker_session);

    let request = QueryRequest {
        get_txos: vec![record.search_key.clone()],
    };
    let aad = mc_util_serial::encode(&QueryRequestAAD {
        start_from_user_event_id: 1,
        start_from_block_index: 0,
    });
    let ciphertext = victim_noise
        .encrypt(&aad, &mc_util_serial::encode(&request))
        .expect("Could not encrypt the victim request.");
    let sealed_query = enclave
        .decrypt_and_seal_query(EnclaveMessage {
            aad: aad.clone(),
            channel_id: victim_session.clone(),
            data: ciphertext,
        })
        .expect("Could not decrypt and seal the victim request.");

    let backend_query = enclave
        .create_multi_view_store_query_data(sealed_query.clone())
        .expect("Could not create the view store query.")
        .pop()
        .expect("Expected a view store query.");
    let backend_response = enclave
        .query_store(
            backend_query,
            UntrustedQueryResponse {
                user_events: vec![],
                next_start_from_user_event_id: 1,
                highest_processed_block_count: 2,
                highest_processed_block_signature_timestamp: 255,
                last_known_block_count: 2,
                last_known_block_cumulative_txo_count: 1,
            },
        )
        .expect("Could not process the view store query.");
    let responses = vec![MultiViewStoreQueryResponse {
        encrypted_query_response: backend_response,
        store_responder_id: responder_id,
        store_uri: "insecure-fog-view-store://view-response-routing.test:3223".to_owned(),
        block_range: BlockRange::new(0, 2),
        status: MultiViewStoreQueryResponseStatus::Success,
    }];

    // Change only the public routing context after the victim query has been
    // authenticated and processed by the store. Keep the sealed bytes and
    // encrypted backend response intact.
    let mut redirected_query = sealed_query.clone();
    redirected_query.channel_id = attacker_session;
    assert!(matches!(
        enclave.collate_shard_query_responses(redirected_query, responses.clone()),
        Err(ViewEnclaveError::AttestEnclave(
            AttestEnclaveError::InvalidState
        ))
    ));

    let mut modified_aad_query = sealed_query.clone();
    modified_aad_query.aad = mc_util_serial::encode(&QueryRequestAAD {
        start_from_user_event_id: 2,
        start_from_block_index: 0,
    });
    assert!(matches!(
        enclave.collate_shard_query_responses(modified_aad_query, responses.clone()),
        Err(ViewEnclaveError::AttestEnclave(
            AttestEnclaveError::InvalidState
        ))
    ));

    // The original context still succeeds, and only the victim's Noise
    // session is needed to decrypt and verify the expected search result.
    let response = enclave
        .collate_shard_query_responses(sealed_query, responses)
        .expect("Could not collate the unmodified victim request.");
    assert_eq!(response.channel_id, victim_session);
    assert_eq!(response.aad, aad);
    let plaintext = victim_noise
        .decrypt(&response.aad, &response.data)
        .expect("Could not decrypt the response with the victim session.");
    let response: QueryResponse = mc_util_serial::decode(&plaintext).unwrap();
    assert_eq!(response.highest_processed_block_count, 2);
    assert_eq!(
        response.fixed_tx_out_search_results,
        vec![FixedTxOutSearchResult::new(
            record.search_key,
            &record.payload,
            TxOutSearchResultCode::Found,
        )]
    );
}
