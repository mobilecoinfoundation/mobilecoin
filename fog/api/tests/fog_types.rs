// Copyright (c) 2018-2021 The MobileCoin Foundation

// Test that mc_fog_types structs match the protos defined in .proto files,
// by testing that they round-trip through the proto-generated rust types

use core::convert::TryFrom;
use mc_crypto_keys::RistrettoPublic;
use mc_fog_api::kex_rng;
use mc_fog_kex_rng::{KexRngPubkey, StoredRng};
use mc_fog_report_api_test_utils::{round_trip_message, round_trip_protobuf_object};
use mc_transaction_core::{
    encrypted_fog_hint::EncryptedFogHint,
    membership_proofs::Range,
    tx::{TxOut, TxOutMembershipElement, TxOutMembershipHash, TxOutMembershipProof},
    Amount, EncryptedMemo,
};
use mc_util_from_random::FromRandom;
use mc_util_test_helper::{run_with_several_seeds, CryptoRng, RngCore};
use mc_watcher_api::TimestampResultCode;

/// Test that many random instances of prosty QueryRequest round trip with
/// protobufy QueryRequest
#[test]
fn fog_view_query_request_round_trip() {
    {
        let test_val: mc_fog_types::view::QueryRequest = Default::default();
        round_trip_message::<mc_fog_types::view::QueryRequest, mc_fog_api::view::QueryRequest>(
            &test_val,
        );
    }

    run_with_several_seeds(|mut rng| {
        let num_txos = rng.next_u32() as u8;
        let test_val = mc_fog_types::view::QueryRequest {
            get_txos: (0..num_txos as usize)
                .map(|_| <[u8; 32]>::sample(&mut rng).to_vec())
                .collect(),
        };
        round_trip_message::<mc_fog_types::view::QueryRequest, mc_fog_api::view::QueryRequest>(
            &test_val,
        );
    });
}

/// Test that many random instances of protobufy QueryRequest round trip with
/// prosty QueryRequesty
#[test]
fn fog_view_query_request_protobuf_round_trip() {
    run_with_several_seeds(|mut rng| {
        let mut test_val = mc_fog_api::view::QueryRequest::new();
        for _ in 0..20 {
            test_val
                .get_txos
                .push(<[u8; 32]>::sample(&mut rng).to_vec());
        }
        round_trip_protobuf_object::<
            mc_fog_api::view::QueryRequest,
            mc_fog_types::view::QueryRequest,
        >(&test_val);
    });
}

/// Test that many random instances of prosty QueryRequestAAD round trip with
/// protobufy QueryRequestAAD
#[test]
fn fog_view_query_request_aad_round_trip() {
    {
        let test_val: mc_fog_types::view::QueryRequestAAD = Default::default();
        round_trip_message::<mc_fog_types::view::QueryRequestAAD, mc_fog_api::view::QueryRequestAAD>(
            &test_val,
        );
    }

    run_with_several_seeds(|mut rng| {
        let test_val = mc_fog_types::view::QueryRequestAAD {
            start_from_user_event_id: rng.next_u64() as i64,
            start_from_block_index: rng.next_u64(),
        };
        round_trip_message::<mc_fog_types::view::QueryRequestAAD, mc_fog_api::view::QueryRequestAAD>(
            &test_val,
        );
    });
}

/// Test that many random instances of protobufy QueryRequestAAD round trip with
/// prosty QueryRequestAADy
#[test]
fn fog_view_query_request_aad_protobuf_round_trip() {
    run_with_several_seeds(|mut rng| {
        let mut test_val = mc_fog_api::view::QueryRequestAAD::new();
        test_val.start_from_user_event_id = rng.next_u64() as i64;
        test_val.start_from_block_index = rng.next_u64();

        round_trip_protobuf_object::<
            mc_fog_api::view::QueryRequestAAD,
            mc_fog_types::view::QueryRequestAAD,
        >(&test_val);
    });

    run_with_several_seeds(|mut rng| {
        let mut test_val = mc_fog_api::view::QueryRequestAAD::new();
        test_val.start_from_user_event_id = rng.next_u64() as i64;
        test_val.start_from_block_index = rng.next_u64();
        round_trip_protobuf_object::<
            mc_fog_api::view::QueryRequestAAD,
            mc_fog_types::view::QueryRequestAAD,
        >(&test_val);
    });
}

/// Test that many random instances of prosty QueryResponse round trip with
/// protobufy QueryResponse
#[test]
fn fog_view_query_response_round_trip() {
    {
        let test_val: mc_fog_types::view::QueryResponse = Default::default();
        round_trip_message::<mc_fog_types::view::QueryResponse, mc_fog_api::view::QueryResponse>(
            &test_val,
        );
    }

    run_with_several_seeds(|mut rng| {
        let test_val = mc_fog_types::view::QueryResponse {
            highest_processed_block_count: rng.next_u64(),
            highest_processed_block_signature_timestamp: rng.next_u64(),
            next_start_from_user_event_id: rng.next_u64() as i64,
            rng_records: (0..20)
                .map(|_| mc_fog_types::view::RngRecord::sample(&mut rng))
                .collect(),
            decommissioned_ingest_invocations: (0..5)
                .map(|_| mc_fog_types::view::DecommissionedIngestInvocation::sample(&mut rng))
                .collect(),
            missed_block_ranges: Default::default(),
            tx_out_search_results: (0..40)
                .map(|_| mc_fog_types::view::TxOutSearchResult::sample(&mut rng))
                .collect(),
            last_known_block_count: rng.next_u32() as u64,
            last_known_block_cumulative_txo_count: rng.next_u32() as u64,
        };
        round_trip_message::<mc_fog_types::view::QueryResponse, mc_fog_api::view::QueryResponse>(
            &test_val,
        );
    });

    run_with_several_seeds(|mut rng| {
        let test_val = mc_fog_types::view::QueryResponse {
            highest_processed_block_count: rng.next_u64(),
            highest_processed_block_signature_timestamp: rng.next_u64(),
            next_start_from_user_event_id: rng.next_u64() as i64,
            rng_records: (0..20)
                .map(|_| mc_fog_types::view::RngRecord::sample(&mut rng))
                .collect(),
            decommissioned_ingest_invocations: (0..5)
                .map(|_| mc_fog_types::view::DecommissionedIngestInvocation::sample(&mut rng))
                .collect(),
            missed_block_ranges: Default::default(),
            tx_out_search_results: (0..40)
                .map(|_| mc_fog_types::view::TxOutSearchResult::sample(&mut rng))
                .collect(),
            last_known_block_count: rng.next_u32() as u64,
            last_known_block_cumulative_txo_count: rng.next_u32() as u64,
        };
        round_trip_message::<mc_fog_types::view::QueryResponse, mc_fog_api::view::QueryResponse>(
            &test_val,
        );
    });

    run_with_several_seeds(|mut rng| {
        let test_val = mc_fog_types::view::QueryResponse {
            highest_processed_block_count: rng.next_u64(),
            highest_processed_block_signature_timestamp: rng.next_u64(),
            next_start_from_user_event_id: rng.next_u64() as i64,
            rng_records: (0..20)
                .map(|_| mc_fog_types::view::RngRecord::sample(&mut rng))
                .collect(),
            decommissioned_ingest_invocations: (0..5)
                .map(|_| mc_fog_types::view::DecommissionedIngestInvocation::sample(&mut rng))
                .collect(),
            missed_block_ranges: (0..10)
                .map(|_| {
                    mc_fog_types::common::BlockRange::new(
                        rng.next_u32() as u64,
                        rng.next_u32() as u64,
                    )
                })
                .collect(),
            tx_out_search_results: (0..40)
                .map(|_| mc_fog_types::view::TxOutSearchResult::sample(&mut rng))
                .collect(),
            last_known_block_count: rng.next_u32() as u64,
            last_known_block_cumulative_txo_count: rng.next_u32() as u64,
        };
        round_trip_message::<mc_fog_types::view::QueryResponse, mc_fog_api::view::QueryResponse>(
            &test_val,
        );
    });
}

/// Test that many random instances of prosty TxOutRecord round trip with
/// protobufy TxOutRecord
#[test]
fn tx_out_record_round_trip() {
    {
        let test_val: mc_fog_types::view::TxOutRecord = Default::default();
        round_trip_message::<mc_fog_types::view::TxOutRecord, mc_fog_api::view::TxOutRecord>(
            &test_val,
        );
    }

    run_with_several_seeds(|mut rng| {
        let fog_txout = mc_fog_types::view::FogTxOut::from(&TxOut::sample(&mut rng));
        let meta = mc_fog_types::view::FogTxOutMetadata {
            global_index: rng.next_u64(),
            block_index: rng.next_u64(),
            timestamp: rng.next_u64(),
        };
        let test_val = mc_fog_types::view::TxOutRecord::new(fog_txout, meta);

        round_trip_message::<mc_fog_types::view::TxOutRecord, mc_fog_api::view::TxOutRecord>(
            &test_val,
        );
    });
}

/// Test that many random instances of prosty GetOutputsResponse round trip with
/// protobufy GetOutputResponse
#[test]
fn get_output_response_round_trip() {
    {
        let test_val = mc_fog_types::ledger::GetOutputsResponse::default();
        round_trip_message::<
            mc_fog_types::ledger::GetOutputsResponse,
            mc_fog_api::ledger::GetOutputsResponse,
        >(&test_val);
    }

    run_with_several_seeds(|mut rng| {
        let mut test_val = mc_fog_types::ledger::GetOutputsResponse::default();
        for _ in 0..20 {
            test_val
                .results
                .push(mc_fog_types::ledger::OutputResult::sample(&mut rng))
        }

        round_trip_message::<
            mc_fog_types::ledger::GetOutputsResponse,
            mc_fog_api::ledger::GetOutputsResponse,
        >(&test_val);
    });
}

/// Test that many random instances of prosty CheckKeyImagesResponse round trip
/// with protobufy CheckKeyImagesResponse
#[test]
fn check_key_images_response_round_trip() {
    {
        let test_val = mc_fog_types::ledger::CheckKeyImagesResponse::default();
        round_trip_message::<
            mc_fog_types::ledger::CheckKeyImagesResponse,
            mc_fog_api::ledger::CheckKeyImagesResponse,
        >(&test_val);
    }

    run_with_several_seeds(|mut rng| {
        let mut test_val = mc_fog_types::ledger::CheckKeyImagesResponse::default();
        test_val.num_blocks = rng.next_u32() as u64;
        test_val.global_txo_count = rng.next_u32() as u64;
        for _ in 0..20 {
            test_val
                .results
                .push(mc_fog_types::ledger::KeyImageResult::sample(&mut rng))
        }

        round_trip_message::<
            mc_fog_types::ledger::CheckKeyImagesResponse,
            mc_fog_api::ledger::CheckKeyImagesResponse,
        >(&test_val);
    });
}

/// Test that .proto enum values match what is in
/// src/fog/recovery_db_iface/src/types.rs
#[test]
fn test_tx_out_search_result_enum_values() {
    assert_eq!(
        mc_fog_types::view::TxOutSearchResultCode::Found as u32,
        mc_fog_api::view::TxOutSearchResultCode::Found as u32
    );
    assert_eq!(
        mc_fog_types::view::TxOutSearchResultCode::NotFound as u32,
        mc_fog_api::view::TxOutSearchResultCode::NotFound as u32
    );
    assert_eq!(
        mc_fog_types::view::TxOutSearchResultCode::BadSearchKey as u32,
        mc_fog_api::view::TxOutSearchResultCode::BadSearchKey as u32
    );
    assert_eq!(
        mc_fog_types::view::TxOutSearchResultCode::InternalError as u32,
        mc_fog_api::view::TxOutSearchResultCode::InternalError as u32
    );
    assert_eq!(
        mc_fog_types::view::TxOutSearchResultCode::RateLimited as u32,
        mc_fog_api::view::TxOutSearchResultCode::RateLimited as u32
    );
}

/// Test that .proto enum values match what is in src/fog_types/ledger.rs
#[test]
fn test_key_image_result_code_enum_values() {
    assert_eq!(
        mc_fog_types::ledger::KeyImageResultCode::Spent as u32,
        mc_fog_api::ledger::KeyImageResultCode::Spent as u32
    );
    assert_eq!(
        mc_fog_types::ledger::KeyImageResultCode::NotSpent as u32,
        mc_fog_api::ledger::KeyImageResultCode::NotSpent as u32
    );
    assert_eq!(
        mc_fog_types::ledger::KeyImageResultCode::KeyImageError as u32,
        mc_fog_api::ledger::KeyImageResultCode::KeyImageError as u32
    );
}

// Test that KexRngPubkey is a subset of its proto
#[test]
fn test_kex_rng_pubkey_round_trip() {
    run_with_several_seeds(|mut rng| {
        let test_val = KexRngPubkey::sample(&mut rng);

        round_trip_message::<KexRngPubkey, kex_rng::KexRngPubkey>(&test_val);
    });
}

// Test that KexRngPubkey proto is a subset of KexRngPubkey
#[test]
fn test_kex_rng_pubkey_round_trip_protobuf() {
    run_with_several_seeds(|mut rng| {
        let mut test_val = kex_rng::KexRngPubkey::new();
        test_val.set_pubkey(<[u8; 32]>::sample(&mut rng).to_vec());
        test_val.version = rng.next_u32();

        round_trip_protobuf_object::<kex_rng::KexRngPubkey, KexRngPubkey>(&test_val);
    });
}

// Test that StoredRng is a subset of its proto
#[test]
fn test_stored_kex_rng_round_trip() {
    run_with_several_seeds(|mut rng| {
        let test_val = StoredRng {
            secret: <[u8; 32]>::sample(&mut rng).to_vec(),
            buffer: <[u8; 16]>::sample(&mut rng).to_vec(),
            counter: rng.next_u64(),
            version: rng.next_u32(),
        };

        round_trip_message::<StoredRng, kex_rng::StoredRng>(&test_val);
    });
}

// Test that StoredRng proto is a subset of StoredRng
#[test]
fn test_stored_kex_rng_round_trip_protobuf() {
    run_with_several_seeds(|mut rng| {
        let mut test_val = kex_rng::StoredRng::new();
        test_val.set_secret(<[u8; 32]>::sample(&mut rng).to_vec());
        test_val.set_buffer(<[u8; 16]>::sample(&mut rng).to_vec());
        test_val.counter = rng.next_u64();
        test_val.version = rng.next_u32();

        round_trip_protobuf_object::<kex_rng::StoredRng, StoredRng>(&test_val);
    });
}

/// These sampling functions are used specifically for these tests, for
/// generating random proto instances to try to round trip.
/// They should not be shipped to production or to customers as part of
/// libmobilecoin They are not done using the mc_crypto_keys::FromRandom trait
/// because we don't need to ship them, and not all of these sampling
/// distributions e.g. Amount::from_random really make sense for any other
/// use-case, we are just generating fuzz data basically.
trait Sample {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self;
}

impl Sample for [u8; 16] {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        let mut result = [0u8; 16];
        rng.fill_bytes(&mut result);
        result
    }
}

impl Sample for [u8; 32] {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        let mut result = [0u8; 32];
        rng.fill_bytes(&mut result);
        result
    }
}

impl Sample for KexRngPubkey {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        let mut result = KexRngPubkey::default();
        result.public_key = <[u8; 32]>::sample(rng).to_vec();
        result.version = rng.next_u32();
        result
    }
}

impl Sample for mc_fog_types::view::RngRecord {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        let mut result = Self::default();
        result.ingest_invocation_id = rng.next_u64() as i64;
        result.pubkey = <KexRngPubkey>::sample(rng);
        result.start_block = rng.next_u64();
        result
    }
}

impl Sample for mc_fog_types::view::DecommissionedIngestInvocation {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        let mut result = Self::default();
        result.ingest_invocation_id = rng.next_u64() as i64;
        result.last_ingested_block = rng.next_u64();
        result
    }
}

impl Sample for mc_fog_types::view::TxOutSearchResult {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        let mut result = Self::default();
        result.search_key = <[u8; 32]>::sample(rng).to_vec();
        result.ciphertext = <[u8; 32]>::sample(rng).to_vec();
        result.result_code = 1;
        result
    }
}

impl Sample for Amount {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Amount::new(rng.next_u32() as u64, &RistrettoPublic::from_random(rng)).unwrap()
    }
}

impl Sample for TxOut {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        TxOut {
            amount: Amount::sample(rng),
            target_key: RistrettoPublic::from_random(rng).into(),
            public_key: RistrettoPublic::from_random(rng).into(),
            e_fog_hint: EncryptedFogHint::fake_onetime_hint(rng),
            e_memo: Option::<EncryptedMemo>::sample(rng),
        }
    }
}

impl Sample for Option<EncryptedMemo> {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        let x = (rng.next_u32() % 256) as u8;
        if x & 1 == 1 {
            return None;
        }

        let bytes = [x; 46];
        Some(EncryptedMemo::try_from(&bytes[..]).unwrap())
    }
}

impl Sample for Range {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        let from = rng.next_u32() as u64;
        let to = from + rng.next_u32() as u64;
        Range { from, to }
    }
}

impl Sample for TxOutMembershipHash {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        TxOutMembershipHash::from(<[u8; 32]>::sample(rng))
    }
}

impl Sample for TxOutMembershipElement {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        TxOutMembershipElement {
            range: Range::sample(rng),
            hash: TxOutMembershipHash::sample(rng),
        }
    }
}

impl Sample for TxOutMembershipProof {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        TxOutMembershipProof {
            index: rng.next_u32() as u64,
            highest_index: rng.next_u32() as u64,
            elements: (0..20)
                .map(|_| TxOutMembershipElement::sample(rng))
                .collect(),
        }
    }
}

impl Sample for mc_fog_types::ledger::OutputResult {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Self {
            index: rng.next_u64(),
            result_code: rng.next_u32(),
            output: TxOut::sample(rng),
            proof: TxOutMembershipProof::sample(rng),
        }
    }
}

impl Sample for mc_fog_types::ledger::KeyImageResult {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Self {
            key_image: mc_transaction_core::ring_signature::KeyImage::sample(rng),
            spent_at: rng.next_u32() as u64,
            timestamp: 11,
            timestamp_result_code: TimestampResultCode::TimestampFound as u32,
            key_image_result_code: mc_fog_types::ledger::KeyImageResultCode::Spent as u32,
        }
    }
}

impl Sample for mc_transaction_core::ring_signature::KeyImage {
    fn sample<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Self::from(rng.next_u64())
    }
}
