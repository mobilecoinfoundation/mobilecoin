// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Tests of the streaming verifier

#![feature(test)]
extern crate test;

use mc_account_keys::{AccountKey, ShortAddressHash};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature_signer::NoKeysRingSigner;
use mc_fog_report_validation_test_utils::{FullyValidatedFogPubkey, MockFogResolver};
use mc_transaction_builder::test_utils::get_unsigned_transaction;
use mc_transaction_core::{
    constants::{MAX_INPUTS, MAX_OUTPUTS, RING_SIZE},
    tx::Tx,
    Amount, BlockVersion, TokenId,
};
use mc_transaction_extra::{verify_tx_summary, TransactionEntity, UnsignedTx};
use mc_util_from_random::FromRandom;
use mc_util_serial::encode;
use rand::{rngs::StdRng, SeedableRng};
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;
use test::Bencher;

// Get an unsigned Tx and the sender account keys with the maximum allowed size
// right now
fn get_current_max_size_transaction(
    rng: &mut impl CryptoRngCore,
) -> (UnsignedTx, AccountKey, AccountKey) {
    let sender = AccountKey::random_with_fog(rng);
    let recipient = AccountKey::random_with_fog(rng);

    let ingest_private_key = RistrettoPrivate::from_random(rng);

    let mut fog_map = BTreeMap::default();
    fog_map.insert(
        recipient
            .default_subaddress()
            .fog_report_url()
            .unwrap()
            .to_string(),
        FullyValidatedFogPubkey {
            pubkey: RistrettoPublic::from(&ingest_private_key),
            pubkey_expiry: 1000,
        },
    );
    let fog_resolver = MockFogResolver(fog_map);

    (
        get_unsigned_transaction(
            BlockVersion::MAX,
            0.into(),
            MAX_INPUTS as usize,
            MAX_OUTPUTS as usize,
            &sender,
            &recipient,
            fog_resolver,
            rng,
        )
        .unwrap(),
        sender,
        recipient,
    )
}

// Get an unsigned Tx and the sender account keys with the minimum possible size
// right now
fn get_current_min_size_transaction(
    rng: &mut impl CryptoRngCore,
) -> (UnsignedTx, AccountKey, AccountKey) {
    let sender = AccountKey::random_with_fog(rng);
    let recipient = AccountKey::random_with_fog(rng);

    let ingest_private_key = RistrettoPrivate::from_random(rng);

    let mut fog_map = BTreeMap::default();
    fog_map.insert(
        recipient
            .default_subaddress()
            .fog_report_url()
            .unwrap()
            .to_string(),
        FullyValidatedFogPubkey {
            pubkey: RistrettoPublic::from(&ingest_private_key),
            pubkey_expiry: 1000,
        },
    );
    let fog_resolver = MockFogResolver(fog_map);

    (
        get_unsigned_transaction(
            BlockVersion::MAX,
            0.into(),
            1,
            1,
            &sender,
            &recipient,
            fog_resolver,
            rng,
        )
        .unwrap(),
        sender,
        recipient,
    )
}

#[test]
fn test_max_size_tx_payload_sizes() {
    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

    let (unsigned_tx, _sender, _recipient) = get_current_max_size_transaction(&mut rng);
    let (signing_data, tx_summary, tx_summary_unblinding_data, _extended_message_digest) =
        unsigned_tx.get_signing_data(&mut rng).unwrap();
    let signature_rct = signing_data
        .sign(&unsigned_tx.rings, &NoKeysRingSigner {}, &mut rng)
        .unwrap();
    let tx = Tx {
        prefix: unsigned_tx.tx_prefix.clone(),
        signature: signature_rct,
        fee_map_digest: Default::default(),
    };

    assert_eq!(tx.prefix.inputs.len(), MAX_INPUTS as usize);
    assert_eq!(tx.prefix.inputs[0].proofs.len(), RING_SIZE as usize);
    assert_eq!(tx.prefix.inputs[0].proofs[0].elements.len(), 32);

    let tx_wire = encode(&tx);
    assert_eq!(tx_wire.len(), 309_238);

    let tx_summary_wire = encode(&tx_summary);
    assert_eq!(tx_summary_wire.len(), 2726);

    let tx_summary_unblinding_wire = encode(&tx_summary_unblinding_data);
    assert_eq!(tx_summary_unblinding_wire.len(), 4690);

    let tx_out_summary_wire = encode(&tx_summary.outputs[0]);
    assert_eq!(tx_out_summary_wire.len(), 129);

    let tx_out_summary_unblinding_wire = encode(&tx_summary_unblinding_data.outputs[0]);
    assert_eq!(tx_out_summary_unblinding_wire.len(), 243);

    let tx_in_summary_wire = encode(&tx_summary.inputs[0]);
    assert_eq!(tx_in_summary_wire.len(), 36);

    let tx_in_summary_unblinding_wire = encode(&tx_summary_unblinding_data.inputs[0]);
    assert_eq!(tx_in_summary_unblinding_wire.len(), 45);
}

#[bench]
fn bench_max_size_zeroize(b: &mut Bencher) {
    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

    let (unsigned_tx, _sender, _recipient) = get_current_max_size_transaction(&mut rng);
    let (signing_data, _tx_summary, _tx_summary_unblinding_data, _extended_message_digest) =
        unsigned_tx.get_signing_data(&mut rng).unwrap();
    let signature_rct = signing_data
        .sign(&unsigned_tx.rings, &NoKeysRingSigner {}, &mut rng)
        .unwrap();
    let tx = Tx {
        prefix: unsigned_tx.tx_prefix.clone(),
        signature: signature_rct,
        fee_map_digest: Default::default(),
    };

    b.iter(|| tx.clone());
}

#[test]
fn test_min_size_tx_payload_sizes() {
    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

    let (unsigned_tx, _sender, _recipient) = get_current_min_size_transaction(&mut rng);
    let (signing_data, tx_summary, tx_summary_unblinding_data, _extended_message_digest) =
        unsigned_tx.get_signing_data(&mut rng).unwrap();
    let signature_rct = signing_data
        .sign(&unsigned_tx.rings, &NoKeysRingSigner {}, &mut rng)
        .unwrap();
    let tx = Tx {
        prefix: unsigned_tx.tx_prefix.clone(),
        signature: signature_rct,
        fee_map_digest: Default::default(),
    };

    assert_eq!(tx.prefix.inputs.len(), 1_usize);
    assert_eq!(tx.prefix.inputs[0].proofs.len(), RING_SIZE as usize);
    assert_eq!(tx.prefix.inputs[0].proofs[0].elements.len(), 32);

    let tx_wire = encode(&tx);
    assert_eq!(tx_wire.len(), 20020);

    let tx_summary_wire = encode(&tx_summary);
    assert_eq!(tx_summary_wire.len(), 176);

    let tx_summary_unblinding_wire = encode(&tx_summary_unblinding_data);
    assert_eq!(tx_summary_unblinding_wire.len(), 295);

    let tx_out_summary_wire = encode(&tx_summary.outputs[0]);
    assert_eq!(tx_out_summary_wire.len(), 129);

    let tx_out_summary_unblinding_wire = encode(&tx_summary_unblinding_data.outputs[0]);
    assert_eq!(tx_out_summary_unblinding_wire.len(), 243);

    let tx_in_summary_wire = encode(&tx_summary.inputs[0]);
    assert_eq!(tx_in_summary_wire.len(), 36);

    let tx_in_summary_unblinding_wire = encode(&tx_summary_unblinding_data.inputs[0]);
    assert_eq!(tx_in_summary_unblinding_wire.len(), 45);
}

#[test]
fn test_max_size_tx_summary_verification() {
    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

    let (unsigned_tx, sender, recipient) = get_current_max_size_transaction(&mut rng);
    let (signing_data, tx_summary, tx_summary_unblinding_data, extended_message_digest) =
        unsigned_tx.get_signing_data(&mut rng).unwrap();

    let (mlsag_signing_digest, report) = verify_tx_summary(
        &extended_message_digest.0.try_into().unwrap(),
        &tx_summary,
        &tx_summary_unblinding_data,
        *sender.view_private_key(),
    )
    .unwrap();
    assert_eq!(
        &mlsag_signing_digest[..],
        &signing_data.mlsag_signing_digest[..]
    );

    let recipient_hash = ShortAddressHash::from(&recipient.default_subaddress());
    let balance_changes: Vec<_> = report.balance_changes.iter().collect();
    assert_eq!(
        balance_changes,
        vec![
            (&(TransactionEntity::Ourself, TokenId::from(0)), &-16000),
            (
                &(TransactionEntity::Address(recipient_hash), TokenId::from(0)),
                &160
            )
        ]
    );
    assert_eq!(report.network_fee, Amount::new(15840, TokenId::from(0)));
}

#[test]
fn test_min_size_tx_summary_verification() {
    let mut rng: StdRng = SeedableRng::from_seed([2u8; 32]);

    let (unsigned_tx, sender, recipient) = get_current_min_size_transaction(&mut rng);
    let (signing_data, tx_summary, tx_summary_unblinding_data, extended_message_digest) =
        unsigned_tx.get_signing_data(&mut rng).unwrap();

    let (mlsag_signing_digest, report) = verify_tx_summary(
        &extended_message_digest.0.try_into().unwrap(),
        &tx_summary,
        &tx_summary_unblinding_data,
        *sender.view_private_key(),
    )
    .unwrap();
    assert_eq!(
        &mlsag_signing_digest[..],
        &signing_data.mlsag_signing_digest[..]
    );

    let recipient_hash = ShortAddressHash::from(&recipient.default_subaddress());
    let balance_changes: Vec<_> = report.balance_changes.iter().collect();
    assert_eq!(
        balance_changes,
        vec![
            (&(TransactionEntity::Ourself, TokenId::from(0)), &-1000),
            (
                &(TransactionEntity::Address(recipient_hash), TokenId::from(0)),
                &10
            )
        ]
    );
    assert_eq!(report.network_fee, Amount::new(990, TokenId::from(0)));
}
