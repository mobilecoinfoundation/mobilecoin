// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_account_keys::AccountKey;
use mc_common::{
    logger::{log, Logger},
    HashSet, ResponderId,
};
use mc_crypto_box::{CryptoBox, VersionedCryptoBox};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_fog_ingest_enclave_api::{IngestEnclave, IngestEnclaveInitParams};
use mc_fog_ingest_enclave_impl::SgxIngestEnclave;
use mc_fog_kex_rng::{BufferedRng, NewFromKex, VersionedKexRng};
use mc_fog_types::{ingest::TxsForIngest, view::FogTxOut};
use mc_fog_view_protocol::{TxOutRecoveryError, UserPrivate};
use mc_oblivious_traits::HeapORAMStorageCreator;
use mc_transaction_core::{
    encrypted_fog_hint::EncryptedFogHint,
    fog_hint::{FogHint, PlaintextArray},
    tx::TxOut,
};
use mc_util_from_random::FromRandom;
use mc_util_logger_macros::test_with_logger;
use mc_util_test_helper::{CryptoRng, RngCore, RngType, SeedableRng};
use std::collections::HashMap;

// Test the ingest enclave impl tx processing
#[test_with_logger]
fn test_ingest_enclave(logger: Logger) {
    mc_util_test_helper::run_with_several_seeds(|mut rng| {
        // make alice and bob
        let alice_account = AccountKey::random_with_fog(&mut rng);
        let bob_account = AccountKey::random_with_fog(&mut rng);

        // make ingest enclave business logic object
        let enclave = SgxIngestEnclave::<HeapORAMStorageCreator>::new(logger.clone());

        let params = IngestEnclaveInitParams {
            responder_id: ResponderId::default(),
            sealed_key: None,
            desired_capacity: 128,
        };

        enclave.enclave_init(params).unwrap();

        // get fog public key
        let fog_pubkey = enclave.get_ingress_pubkey().unwrap();

        // get kex rng pubkey
        let kex_rng_pubkey = enclave.get_kex_rng_pubkey().unwrap();

        let bob_public_address = bob_account.default_subaddress();

        // make some tx outs
        let tx_outs_for_bob: Vec<_> = (0..10)
            .map(|_| {
                let tx_private_key = RistrettoPrivate::from_random(&mut rng);
                let e_fog_hint = FogHint::from(&bob_public_address).encrypt(&fog_pubkey, &mut rng);
                TxOut::new(
                    10,
                    &bob_account.default_subaddress(),
                    &tx_private_key,
                    e_fog_hint,
                )
                .unwrap()
            })
            .collect();

        // make txs_for_ingest object
        let timestamp = 10;
        let txs_for_ingest = TxsForIngest {
            block_index: 1,
            global_txo_index: 100,
            redacted_txs: tx_outs_for_bob.clone(),
            timestamp,
        };

        // submit txs to enclave
        let (tx_rows, maybe_kex_rng_pubkey) = enclave.ingest_txs(txs_for_ingest.clone()).unwrap();
        assert!(maybe_kex_rng_pubkey.is_none()); // rng store should not have rotated

        // Check that the right number of txs came back
        assert_eq!(tx_rows.len(), 10);

        // Check that the tx row ciphertexts have the right size
        const EXPECTED_PAYLOAD_SIZE: usize = 207; // The observed tx_row.payload size
        for tx_row in tx_rows.iter() {
            assert_eq!(
                tx_row.payload.len(), EXPECTED_PAYLOAD_SIZE,
                "tx_row payload didnt have expected length, should be constant size for security purposes, so that they are all indistinguishable",
            );
        }

        // check that Bob's crypto math works out
        let bob_fog_credential = UserPrivate::from(&bob_account);

        // Check that the search keys on the tx rows match Bob's rng
        {
            let mut bob_rng = VersionedKexRng::try_from_kex_pubkey(
                &kex_rng_pubkey,
                bob_fog_credential.get_view_key(),
            )
            .unwrap();
            let mut search_keys: HashSet<_> =
                tx_rows.iter().map(|row| row.search_key.clone()).collect();
            assert!(
                search_keys.len() == tx_rows.len(),
                "Fog search key collisions, that is bad: {}/{} unique search keys",
                search_keys.len(),
                tx_rows.len()
            );
            while !search_keys.is_empty() {
                let output = bob_rng.next().unwrap();
                let was_present = search_keys.remove(&output);
                assert!(
                    was_present,
                    "Did not find output for bob_rng index {}",
                    bob_rng.index() - 1
                );
            }
        }

        // Check that Bob can decrypt the payloads for each tx row
        for idx in 0..10 {
            let tx_out_record = bob_fog_credential
                .decrypt_tx_out_result(tx_rows[idx].payload.clone())
                .unwrap();
            assert_eq!(tx_out_record.block_index, txs_for_ingest.block_index);
            assert_eq!(
                tx_out_record.tx_out_global_index,
                txs_for_ingest.global_txo_index + idx as u64
            );
            assert_eq!(
                tx_out_record.get_fog_tx_out().unwrap(),
                FogTxOut::from(&tx_outs_for_bob[idx])
            );
        }

        // Check that Alice cannot decrypt the payloads for each tx row
        let alice_fog_credential = UserPrivate::from(&alice_account);
        for idx in 0..10 {
            if let Ok(_) = alice_fog_credential.decrypt_tx_out_result(tx_rows[idx].payload.clone())
            {
                panic!("Alice should not have been able to decrypt the tx row!");
            }
        }
    })
}

// This fog hint has a valid curve point, but invalid magic bytes
fn make_malformed_fog_hint<T: RngCore + CryptoRng>(
    ingress_pubkey: &RistrettoPublic,
    rng: &mut T,
) -> EncryptedFogHint {
    let mut plaintext = PlaintextArray::default();

    let bytes = VersionedCryptoBox::default()
        .encrypt_fixed_length(rng, ingress_pubkey, &mut plaintext)
        .expect("cryptobox encryption failed unexpectedly");
    EncryptedFogHint::from(bytes)
}

// This fog hint has valid magic bytes, but an invalid curve point
fn make_malformed_fog_hint2<T: RngCore + CryptoRng>(
    ingress_pubkey: &RistrettoPublic,
    rng: &mut T,
) -> EncryptedFogHint {
    let mut plaintext = PlaintextArray::default();

    // Make the first 32 bytes not a valid curve point
    plaintext[0] = !0;

    // Set magic bytes correctly
    for byte in &mut plaintext[32..] {
        *byte = 42u8;
    }

    let bytes = VersionedCryptoBox::default()
        .encrypt_fixed_length(rng, ingress_pubkey, &mut plaintext)
        .expect("cryptobox encryption failed unexpectedly");
    EncryptedFogHint::from(bytes)
}

// Test the ingest enclave impl behavior when malformed txos are present
#[test_with_logger]
fn test_ingest_enclave_malformed_txos(logger: Logger) {
    mc_util_test_helper::run_with_several_seeds(|mut rng| {
        // make bob
        let bob_account = AccountKey::random_with_fog(&mut rng);

        // make ingest enclave business logic object
        let enclave = SgxIngestEnclave::<HeapORAMStorageCreator>::new(logger.clone());

        let params = IngestEnclaveInitParams {
            responder_id: ResponderId::default(),
            sealed_key: None,
            desired_capacity: 128,
        };

        enclave.enclave_init(params).unwrap();

        // get fog public key
        let fog_pubkey = enclave.get_ingress_pubkey().unwrap();

        // get kex rng pubkey
        let kex_rng_pubkey = enclave.get_kex_rng_pubkey().unwrap();

        let bob_public_address = bob_account.default_subaddress();

        // make some tx outs
        let tx_outs: Vec<_> = (0..40usize)
            .map(|idx| {
                let tx_private_key = RistrettoPrivate::from_random(&mut rng);
                let e_fog_hint = match idx % 4 {
                    // This fog hint is correctly formed for Bob
                    0 => FogHint::from(&bob_public_address).encrypt(&fog_pubkey, &mut rng),
                    // This fog hint is built as for a non-fog user
                    1 => EncryptedFogHint::fake_onetime_hint(&mut rng),
                    // This fog hint is malformed, and doesn't have the right magic bytes
                    2 => make_malformed_fog_hint(&fog_pubkey, &mut rng),
                    // This fog hint is malformed, and is properly encrypted but contains something
                    // that isn't an elliptic curve point
                    3 => make_malformed_fog_hint2(&fog_pubkey, &mut rng),
                    _ => panic!("this should be unreachable"),
                };
                TxOut::new(
                    10,
                    &bob_account.default_subaddress(),
                    &tx_private_key,
                    e_fog_hint,
                )
                .unwrap()
            })
            .collect();

        // make txs_for_ingest object
        let timestamp = 10;
        let txs_for_ingest = TxsForIngest {
            block_index: 1,
            global_txo_index: 100,
            redacted_txs: tx_outs.clone(),
            timestamp,
        };

        // submit txs to enclave
        let (tx_rows, maybe_kex_rng_pubkey) = enclave.ingest_txs(txs_for_ingest.clone()).unwrap();
        assert!(maybe_kex_rng_pubkey.is_none()); // rng store should not have rotated

        // Check that the right number of txs came back. Every fourth tx doesn't lead to
        // a tx row, because of bad curve point
        assert_eq!(tx_rows.len(), 40 * 3 / 4);

        // check that Bob's crypto math works out
        let bob_fog_credential = UserPrivate::from(&bob_account);

        // Check that the search keys on the tx rows match Bob's rng
        {
            let mut bob_rng = VersionedKexRng::try_from_kex_pubkey(
                &kex_rng_pubkey,
                bob_fog_credential.get_view_key(),
            )
            .unwrap();
            for (index3, some_rows) in tx_rows.chunks(3).enumerate() {
                let bob_search_key = bob_rng.next().unwrap();
                assert_eq!(some_rows.len(), 3);
                assert_eq!(
                    some_rows[0].search_key, bob_search_key,
                    "unexpected search key for {}'th tx for Bob",
                    index3
                );
                assert_ne!(some_rows[1].search_key, bob_search_key);
                assert_ne!(some_rows[2].search_key, bob_search_key);

                let tx_out_record = bob_fog_credential
                    .decrypt_tx_out_result(some_rows[0].payload.clone())
                    .expect("Bob couldn't decrypt his row");
                assert_eq!(tx_out_record.block_index, txs_for_ingest.block_index);
                assert_eq!(
                    tx_out_record.tx_out_global_index,
                    txs_for_ingest.global_txo_index + (4 * index3 as u64) /* This is 4 for each
                                                                           * 3 chunks of
                                                                           * tx_rows, there were
                                                                           * 4 tx_outs */
                );
                assert_eq!(
                    tx_out_record.get_fog_tx_out().unwrap(),
                    FogTxOut::from(&tx_outs[4 * index3])
                );

                assert!(
                    bob_fog_credential
                        .decrypt_tx_out_result(some_rows[1].payload.clone())
                        .is_err(),
                    "expected failure to decrypt bad row: {}",
                    index3 * 3 + 1
                );
                assert!(
                    bob_fog_credential
                        .decrypt_tx_out_result(some_rows[2].payload.clone())
                        .is_err(),
                    "expected failure to decrypt bad row: {}",
                    index3 * 3 + 2
                );
            }
        }
    })
}

// Test the ingest enclave impl tx processing when overflow is expected
#[test_with_logger]
fn test_ingest_enclave_overflow(logger: Logger) {
    let mut rng = RngType::from_seed([0u8; 32]);

    // make alice and bob
    let alice_account = AccountKey::random_with_fog(&mut rng);
    let bob_account = AccountKey::random_with_fog(&mut rng);

    let alice_public_address = alice_account.default_subaddress();
    let bob_public_address = bob_account.default_subaddress();

    // Repeat the test 5 times to try to smoke out failures
    let repetitions = 5;
    for iteration in 0..repetitions {
        log::info!(
            logger,
            "test_ingest_enclave_overflow {}/{}",
            iteration,
            repetitions
        );

        // make ingest enclave business logic object
        let enclave = SgxIngestEnclave::<HeapORAMStorageCreator>::new(logger.clone());

        let params = IngestEnclaveInitParams {
            responder_id: ResponderId::default(),
            sealed_key: None,
            desired_capacity: 128,
        };

        enclave.enclave_init(params).unwrap();

        // get fog public key
        let fog_pubkey = enclave.get_ingress_pubkey().unwrap();

        // get kex rng pubkey
        let mut kex_rng_pubkeys = vec![enclave.get_kex_rng_pubkey().unwrap()];

        log::info!(logger, "Creating and processing TxOut's");
        let mut global_txo_index = 0u64;
        let mut all_tx_outs = Vec::new();
        let mut all_tx_rows = Vec::new();

        const TXS_PER_CHUNK: usize = 50;
        // Force the enclave to overflow at least once, since we started it with small
        // capacity
        for iteration in 0..10 {
            // make some tx outs, each for alice or bob
            let tx_outs: Vec<_> = (0..TXS_PER_CHUNK)
                .map(|_| {
                    let pub_addr = if rng.next_u32() % 2 == 0 {
                        &alice_public_address
                    } else {
                        &bob_public_address
                    };
                    let tx_private_key = RistrettoPrivate::from_random(&mut rng);
                    let e_fog_hint = FogHint::from(pub_addr).encrypt(&fog_pubkey, &mut rng);
                    TxOut::new(10, pub_addr, &tx_private_key, e_fog_hint).unwrap()
                })
                .collect();

            all_tx_outs.extend(tx_outs.clone());

            // make txs_for_ingest object
            let timestamp = 10;
            let txs_for_ingest = TxsForIngest {
                block_index: 1,
                global_txo_index,
                redacted_txs: tx_outs.clone(),
                timestamp,
            };

            global_txo_index += tx_outs.len() as u64;

            // submit txs to enclave
            let (tx_rows, maybe_kex_rng_pubkey) =
                enclave.ingest_txs(txs_for_ingest.clone()).unwrap();

            // Check that the right number of txs came back
            assert_eq!(tx_rows.len(), TXS_PER_CHUNK);
            all_tx_rows.extend(tx_rows);

            if let Some(kex_rng_pubkey) = maybe_kex_rng_pubkey {
                log::info!(
                    logger,
                    "Rotated kex rng: iteration = {} , global_txo_index = {}",
                    iteration,
                    global_txo_index
                );
                kex_rng_pubkeys.push(kex_rng_pubkey);
            }
        }
        assert!(
            kex_rng_pubkeys.len() > 1,
            "Expected to rotate at least once"
        );

        log::info!(logger, "Validating outputs");
        {
            let mut key_exchange_messages = HashMap::<Vec<u8>, usize>::default();
            for (idx, kex_rng_pubkey) in kex_rng_pubkeys.iter().enumerate() {
                if let Some(prev) =
                    key_exchange_messages.insert(kex_rng_pubkey.public_key.clone(), idx)
                {
                    panic!(
                        "kex rng {}'th was a duplicate of {}: {:?}",
                        idx, prev, kex_rng_pubkey.public_key
                    );
                }
            }

            let mut search_keys = HashMap::<Vec<u8>, usize>::default();
            for (idx, tx_row) in all_tx_rows.iter().enumerate() {
                if let Some(prev) = search_keys.insert(tx_row.search_key.clone(), idx) {
                    panic!(
                        "search key for {}'th row was a duplicate of row {}: {:?}",
                        idx, prev, tx_row.search_key
                    );
                }
            }
        }

        log::info!(logger, "Matching ETxOutRows with RNG's and decrypting");

        // Check that alice and bob can actually recover all of the transactions, and
        // each one only recovers one
        let alice_fog_credential = UserPrivate::from(&alice_account);
        let bob_fog_credential = UserPrivate::from(&bob_account);

        let mut alice_rngs: Vec<_> = kex_rng_pubkeys
            .iter()
            .map(|kex_rng_pubkey| {
                VersionedKexRng::try_from_kex_pubkey(
                    &kex_rng_pubkey,
                    alice_fog_credential.get_view_key(),
                )
                .expect("Could not form kex rng")
            })
            .collect();

        let mut bob_rngs: Vec<_> = kex_rng_pubkeys
            .iter()
            .map(|kex_rng_pubkey| {
                VersionedKexRng::try_from_kex_pubkey(
                    &kex_rng_pubkey,
                    bob_fog_credential.get_view_key(),
                )
                .expect("Could not form kex rng")
            })
            .collect();

        // Try to match every tx row against every one of  rng's
        for (idx, tx_row) in all_tx_rows.iter().enumerate() {
            let mut alice_found = false;
            for rng in alice_rngs.iter_mut() {
                if rng.peek() == &tx_row.search_key[..] {
                    rng.advance();
                    alice_found = true;
                }
            }

            let mut bob_found = false;
            for rng in bob_rngs.iter_mut() {
                if rng.peek() == &tx_row.search_key[..] {
                    rng.advance();
                    bob_found = true;
                }
            }

            assert!(
                alice_found || bob_found,
                "Could not match {}'th tx row to Alice's or Bob's RNG's",
                idx
            );
            assert!(
                !alice_found || !bob_found,
                "Matched {}'th tx row to BOTH Alice and to Bob",
                idx
            );

            match alice_fog_credential.decrypt_tx_out_result(tx_row.payload.clone()) {
                Ok(tx_out_record) => {
                    assert_eq!(
                        tx_out_record.tx_out_global_index, idx as u64,
                        "{:?} {:?} alice:{} bob:{}",
                        tx_out_record, tx_row, alice_found, bob_found,
                    );
                    let expected_fog_tx_out = FogTxOut::from(&all_tx_outs[idx]);
                    assert_eq!(
                        tx_out_record.get_fog_tx_out().unwrap(),
                        expected_fog_tx_out,
                        "{:?} {:?}",
                        tx_out_record,
                        tx_row,
                    );
                    assert_eq!(
                        tx_out_record.block_index, 1,
                        "{:?} {:?}",
                        tx_out_record, tx_row
                    );
                    assert!(
                        alice_found,
                        "Alice wasn't supposed to be able to decrypt {}'th tx row. bob_found = {}: {:?} {:?}",
                        idx, bob_found, tx_out_record, tx_row,
                    );
                }
                Err(err @ TxOutRecoveryError::MacCheckFailed) => {
                    assert!(
                        !alice_found,
                        "Alice was supposed to be able to decrypt {}'th tx row: {}",
                        idx, err
                    );
                }
                Err(err) => {
                    panic!("Alice got an unexpected error when attempting to decrypt {}'th tx row: {}. alice_found = {}",
                        idx, err, alice_found
                    );
                }
            };

            match bob_fog_credential.decrypt_tx_out_result(tx_row.payload.clone()) {
                Ok(tx_out_record) => {
                    assert_eq!(
                        tx_out_record.tx_out_global_index, idx as u64,
                        "{:?} {:?} alice:{} bob:{}",
                        tx_out_record, tx_row, alice_found, bob_found,
                    );
                    let expected_fog_tx_out = FogTxOut::from(&all_tx_outs[idx]);
                    assert_eq!(
                        tx_out_record.get_fog_tx_out().unwrap(),
                        expected_fog_tx_out,
                        "{:?} {:?}",
                        tx_out_record,
                        tx_row,
                    );
                    assert_eq!(
                        tx_out_record.block_index, 1,
                        "{:?} {:?}",
                        tx_out_record, tx_row
                    );
                    assert!(
                        bob_found,
                        "Bob wasn't supposed to be able to decrypt {}'th tx row. alice_found = {}: {:?} {:?}",
                        idx, alice_found, tx_out_record, tx_row,
                    );
                }
                Err(err @ TxOutRecoveryError::MacCheckFailed) => {
                    assert!(
                        !bob_found,
                        "Bob was supposed to be able to decrypt {}'th tx row: {}",
                        idx, err
                    );
                }
                Err(err) => {
                    panic!("Bob got an unexpected error when attempting to decrypt {}'th tx row: {}. bob_found = {}",
                        idx, err, bob_found
                    );
                }
            };
        }
    }
}
