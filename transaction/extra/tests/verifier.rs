// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Tests of the streaming verifier

use mc_account_keys::{AccountKey, ShortAddressHash};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature_signer::NoKeysRingSigner;
use mc_fog_report_validation_test_utils::{FullyValidatedFogPubkey, MockFogResolver};
use mc_transaction_builder::{
    test_utils::{get_input_credentials, get_unsigned_transaction},
    DefaultTxOutputsOrdering, EmptyMemoBuilder, ReservedSubaddresses, SignedContingentInputBuilder,
    TransactionBuilder,
};
use mc_transaction_core::{
    constants::{MAX_INPUTS, MAX_OUTPUTS, MILLIMOB_TO_PICOMOB, RING_SIZE},
    tokens::Mob,
    tx::Tx,
    Amount, BlockVersion, Token, TokenId,
};
use mc_transaction_extra::UnsignedTx;
use mc_transaction_summary::{verify_tx_summary, TransactionEntity};
use mc_util_from_random::FromRandom;
use mc_util_serial::encode;
use rand::{rngs::StdRng, SeedableRng};
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;

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
    assert_eq!(tx.prefix.inputs[0].proofs.len(), { RING_SIZE });
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
    assert_eq!(tx.prefix.inputs[0].proofs.len(), { RING_SIZE });
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
        sender.change_subaddress(),
    )
    .unwrap();
    assert_eq!(
        &mlsag_signing_digest[..],
        &signing_data.mlsag_signing_digest[..]
    );

    let recipient_hash = ShortAddressHash::from(&recipient.default_subaddress());
    assert_eq!(
        &report.outputs,
        &[(
            TransactionEntity::OtherAddress(recipient_hash),
            TokenId::from(0),
            160
        )]
    );
    assert_eq!(&report.totals, &[(TokenId::from(0), 16000),]);

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
        sender.change_subaddress(),
    )
    .unwrap();
    assert_eq!(
        &mlsag_signing_digest[..],
        &signing_data.mlsag_signing_digest[..]
    );

    let recipient_hash = ShortAddressHash::from(&recipient.default_subaddress());
    assert_eq!(
        &report.outputs,
        &[(
            TransactionEntity::OtherAddress(recipient_hash),
            TokenId::from(0),
            10
        )]
    );
    assert_eq!(&report.totals, &[(TokenId::from(0), 1000),]);
    assert_eq!(report.network_fee, Amount::new(990, TokenId::from(0)));
}

// Build a transaction with two inputs using the transaction builder and test
// TxSummary verifier
#[test]
fn test_two_input_tx_with_change_tx_summary_verification() {
    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

    let block_version = BlockVersion::MAX;
    for token_id in [TokenId::from(0), TokenId::from(1)] {
        let fog_resolver = MockFogResolver::default();
        let sender = AccountKey::random(&mut rng);
        let sender_change_dest = ReservedSubaddresses::from(&sender);
        let recipient = AccountKey::random(&mut rng);
        let recipient_address = recipient.default_subaddress();
        let value = 1475 * MILLIMOB_TO_PICOMOB;
        let value2 = 1000 * MILLIMOB_TO_PICOMOB;
        let change_value = 128 * MILLIMOB_TO_PICOMOB;

        let mut transaction_builder = TransactionBuilder::new(
            block_version,
            Amount::new(Mob::MINIMUM_FEE, token_id),
            fog_resolver.clone(),
            EmptyMemoBuilder::default(),
        )
        .unwrap();

        transaction_builder.set_tombstone_block(2000);

        let input_credentials = get_input_credentials(
            block_version,
            Amount::new(value, token_id),
            &sender,
            &fog_resolver,
            &mut rng,
        );
        transaction_builder.add_input(input_credentials);
        let input_credentials = get_input_credentials(
            block_version,
            Amount::new(value2, token_id),
            &sender,
            &fog_resolver,
            &mut rng,
        );
        transaction_builder.add_input(input_credentials);

        transaction_builder
            .add_output(
                Amount::new(value + value2 - change_value - Mob::MINIMUM_FEE, token_id),
                &recipient_address,
                &mut rng,
            )
            .unwrap();

        transaction_builder
            .add_change_output(
                Amount::new(change_value, token_id),
                &sender_change_dest,
                &mut rng,
            )
            .unwrap();

        let unsigned_tx = transaction_builder
            .build_unsigned::<DefaultTxOutputsOrdering>()
            .unwrap();

        let (signing_data, tx_summary, tx_summary_unblinding_data, extended_message_digest) =
            unsigned_tx.get_signing_data(&mut rng).unwrap();

        let (mlsag_signing_digest, report) = verify_tx_summary(
            &extended_message_digest.0.try_into().unwrap(),
            &tx_summary,
            &tx_summary_unblinding_data,
            *sender.view_private_key(),
            sender.change_subaddress(),
        )
        .unwrap();
        assert_eq!(
            &mlsag_signing_digest[..],
            &signing_data.mlsag_signing_digest[..]
        );

        let recipient_hash = ShortAddressHash::from(&recipient.default_subaddress());
        assert_eq!(
            &report.totals,
            &[(token_id, (value + value2 - change_value) as i64),]
        );
        assert_eq!(
            &report.outputs,
            &[(
                TransactionEntity::OtherAddress(recipient_hash),
                token_id,
                (value + value2 - change_value - Mob::MINIMUM_FEE)
            ),]
        );
        assert_eq!(report.network_fee, Amount::new(Mob::MINIMUM_FEE, token_id));
    }
}

// Build a basic transaction using the transaction builder and test TxSummary
// verifier
#[test]
fn test_simple_tx_with_change_tx_summary_verification() {
    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

    let block_version = BlockVersion::MAX;
    for token_id in [TokenId::from(0), TokenId::from(1)] {
        let fog_resolver = MockFogResolver::default();
        let sender = AccountKey::random(&mut rng);
        let sender_change_dest = ReservedSubaddresses::from(&sender);
        let recipient = AccountKey::random(&mut rng);
        let recipient_address = recipient.default_subaddress();
        let value = 1475 * MILLIMOB_TO_PICOMOB;
        let change_value = 128 * MILLIMOB_TO_PICOMOB;

        let mut transaction_builder = TransactionBuilder::new(
            block_version,
            Amount::new(Mob::MINIMUM_FEE, token_id),
            fog_resolver.clone(),
            EmptyMemoBuilder::default(),
        )
        .unwrap();

        transaction_builder.set_tombstone_block(2000);

        let input_credentials = get_input_credentials(
            block_version,
            Amount::new(value, token_id),
            &sender,
            &fog_resolver,
            &mut rng,
        );
        transaction_builder.add_input(input_credentials);

        transaction_builder
            .add_output(
                Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                &recipient_address,
                &mut rng,
            )
            .unwrap();

        transaction_builder
            .add_change_output(
                Amount::new(change_value, token_id),
                &sender_change_dest,
                &mut rng,
            )
            .unwrap();

        let unsigned_tx = transaction_builder
            .build_unsigned::<DefaultTxOutputsOrdering>()
            .unwrap();

        let (signing_data, tx_summary, tx_summary_unblinding_data, extended_message_digest) =
            unsigned_tx.get_signing_data(&mut rng).unwrap();

        let (mlsag_signing_digest, report) = verify_tx_summary(
            &extended_message_digest.0.try_into().unwrap(),
            &tx_summary,
            &tx_summary_unblinding_data,
            *sender.view_private_key(),
            sender.change_subaddress(),
        )
        .unwrap();
        assert_eq!(
            &mlsag_signing_digest[..],
            &signing_data.mlsag_signing_digest[..]
        );

        let recipient_hash = ShortAddressHash::from(&recipient.default_subaddress());
        assert_eq!(
            &report.totals,
            &[(token_id, ((value - change_value) as i64)),]
        );
        assert_eq!(
            &report.outputs,
            &[(
                TransactionEntity::OtherAddress(recipient_hash),
                token_id,
                (value - change_value - Mob::MINIMUM_FEE)
            ),]
        );
        assert_eq!(report.network_fee, Amount::new(Mob::MINIMUM_FEE, token_id));
    }
}

// Build a transaction with two recipients using the transaction builder and
// test TxSummary verifier
#[test]
fn test_two_output_tx_with_change_tx_summary_verification() {
    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

    let block_version = BlockVersion::MAX;
    for token_id in [TokenId::from(0), TokenId::from(1)] {
        let fog_resolver = MockFogResolver::default();
        let sender = AccountKey::random(&mut rng);
        let sender_change_dest = ReservedSubaddresses::from(&sender);
        let recipient = AccountKey::random(&mut rng);
        let recipient_address = recipient.default_subaddress();
        let recipient2 = AccountKey::random(&mut rng);
        let recipient2_address = recipient2.default_subaddress();
        let value = 1475 * MILLIMOB_TO_PICOMOB;
        let value2 = 1000 * MILLIMOB_TO_PICOMOB;
        let change_value = 128 * MILLIMOB_TO_PICOMOB;

        let mut transaction_builder = TransactionBuilder::new(
            block_version,
            Amount::new(Mob::MINIMUM_FEE, token_id),
            fog_resolver.clone(),
            EmptyMemoBuilder::default(),
        )
        .unwrap();

        transaction_builder.set_tombstone_block(2000);

        let input_credentials = get_input_credentials(
            block_version,
            Amount::new(value + value2 + change_value + Mob::MINIMUM_FEE, token_id),
            &sender,
            &fog_resolver,
            &mut rng,
        );
        transaction_builder.add_input(input_credentials);

        transaction_builder
            .add_output(Amount::new(value, token_id), &recipient_address, &mut rng)
            .unwrap();

        transaction_builder
            .add_output(Amount::new(value2, token_id), &recipient2_address, &mut rng)
            .unwrap();

        transaction_builder
            .add_change_output(
                Amount::new(change_value, token_id),
                &sender_change_dest,
                &mut rng,
            )
            .unwrap();

        let unsigned_tx = transaction_builder
            .build_unsigned::<DefaultTxOutputsOrdering>()
            .unwrap();

        let (signing_data, tx_summary, tx_summary_unblinding_data, extended_message_digest) =
            unsigned_tx.get_signing_data(&mut rng).unwrap();

        let (mlsag_signing_digest, report) = verify_tx_summary(
            &extended_message_digest.0.try_into().unwrap(),
            &tx_summary,
            &tx_summary_unblinding_data,
            *sender.view_private_key(),
            sender.change_subaddress(),
        )
        .unwrap();
        assert_eq!(
            &mlsag_signing_digest[..],
            &signing_data.mlsag_signing_digest[..]
        );

        let recipient_hash = ShortAddressHash::from(&recipient.default_subaddress());
        let recipient2_hash = ShortAddressHash::from(&recipient2.default_subaddress());
        assert_eq!(
            &report.totals,
            &[(token_id, (value + value2 + Mob::MINIMUM_FEE) as i64),]
        );
        let mut outputs = vec![
            (
                TransactionEntity::OtherAddress(recipient_hash),
                token_id,
                value,
            ),
            (
                TransactionEntity::OtherAddress(recipient2_hash),
                token_id,
                value2,
            ),
        ];
        outputs.sort();
        assert_eq!(&report.outputs[..], &outputs[..]);
        assert_eq!(report.network_fee, Amount::new(Mob::MINIMUM_FEE, token_id));
    }
}

// Build a transaction using a signed contingent input, and test TxSummary
// verifier
#[test]
fn test_sci_tx_summary_verification() {
    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

    let block_version = BlockVersion::MAX;

    let fog_resolver = MockFogResolver::default();

    let alice = AccountKey::random(&mut rng);
    let bob = AccountKey::random(&mut rng);

    let value = 1475 * MILLIMOB_TO_PICOMOB;
    let amount = Amount::new(value, Mob::ID);
    let token2 = TokenId::from(2);
    let value2 = 100_000;
    let amount2 = Amount::new(value2, token2);

    // Alice provides amount of Mob
    let input_credentials =
        get_input_credentials(block_version, amount, &alice, &fog_resolver, &mut rng);

    let proofs = input_credentials.membership_proofs.clone();

    let mut builder = SignedContingentInputBuilder::new(
        block_version,
        input_credentials,
        fog_resolver.clone(),
        EmptyMemoBuilder::default(),
    )
    .unwrap();

    // Alice requests amount2 worth of token id 2 in exchange
    let (_txout, _confirmation) = builder
        .add_required_output(amount2, &alice.default_subaddress(), &mut rng)
        .unwrap();

    let mut sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

    // The contingent input should have a valid signature.
    sci.validate().unwrap();

    // Bob has 3x worth of token id 2
    let input_credentials = get_input_credentials(
        block_version,
        Amount::new(300_000, token2),
        &bob,
        &fog_resolver,
        &mut rng,
    );

    let mut builder = TransactionBuilder::new(
        block_version,
        Amount::new(Mob::MINIMUM_FEE, Mob::ID),
        fog_resolver,
        EmptyMemoBuilder::default(),
    )
    .unwrap();

    // Bob supplies his (excess) token id 2
    builder.add_input(input_credentials);

    // Bob adds the presigned input, which also adds the required outputs
    sci.tx_in.proofs = proofs;
    builder.add_presigned_input(sci).unwrap();

    let bob_change_dest = ReservedSubaddresses::from(&bob);

    // Bob keeps the change from token id 2
    builder
        .add_change_output(Amount::new(200_000, token2), &bob_change_dest, &mut rng)
        .unwrap();

    // Bob keeps the Mob that Alice supplies, less fees
    builder
        .add_output(
            Amount::new(value - Mob::MINIMUM_FEE, Mob::ID),
            &bob.default_subaddress(),
            &mut rng,
        )
        .unwrap();
    let bob_hash = ShortAddressHash::from(&bob.default_subaddress());

    let unsigned_tx = builder
        .build_unsigned::<DefaultTxOutputsOrdering>()
        .unwrap();

    let (signing_data, tx_summary, tx_summary_unblinding_data, extended_message_digest) =
        unsigned_tx.get_signing_data(&mut rng).unwrap();

    let (mlsag_signing_digest, report) = verify_tx_summary(
        &extended_message_digest.0.try_into().unwrap(),
        &tx_summary,
        &tx_summary_unblinding_data,
        *bob.view_private_key(),
        bob.change_subaddress(),
    )
    .unwrap();
    assert_eq!(
        &mlsag_signing_digest[..],
        &signing_data.mlsag_signing_digest[..]
    );

    // TODO: fix this test
    assert_eq!(
        &report.totals,
        &[
            // Bob spends 3x worth of token id 2 in the transaction
            (token2, value2 as i64),
        ]
    );
    let mut outputs = vec![
        // Output to swap counterparty
        (TransactionEntity::Swap, token2, value2),
        // Converted output to ourself
        (
            TransactionEntity::OurAddress(bob_hash),
            Mob::ID,
            value - Mob::MINIMUM_FEE,
        ),
    ];
    outputs.sort();
    assert_eq!(&report.outputs[..], &outputs[..]);

    assert_eq!(report.network_fee, Amount::new(Mob::MINIMUM_FEE, Mob::ID));
}

// Build a transaction using a signed contingent input that sends to a friend,
// and test TxSummary verifier
#[test]
fn test_sci_three_way_tx_summary_verification() {
    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

    let block_version = BlockVersion::MAX;

    let fog_resolver = MockFogResolver::default();

    let alice = AccountKey::random(&mut rng);
    let bob = AccountKey::random(&mut rng);
    let charlie = AccountKey::random(&mut rng);

    let value = 1475 * MILLIMOB_TO_PICOMOB;
    let amount = Amount::new(value, Mob::ID);
    let token2 = TokenId::from(2);
    let value2 = 100_000;
    let amount2 = Amount::new(value2, token2);

    // Alice provides amount of Mob
    let input_credentials =
        get_input_credentials(block_version, amount, &alice, &fog_resolver, &mut rng);

    let proofs = input_credentials.membership_proofs.clone();

    let mut builder = SignedContingentInputBuilder::new(
        block_version,
        input_credentials,
        fog_resolver.clone(),
        EmptyMemoBuilder::default(),
    )
    .unwrap();

    // Alice requests amount2 worth of token id 2 in exchange
    let (_txout, _confirmation) = builder
        .add_required_output(amount2, &alice.default_subaddress(), &mut rng)
        .unwrap();

    let mut sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

    // The contingent input should have a valid signature.
    sci.validate().unwrap();

    // Bob has 3x worth of token id 2
    let input_credentials = get_input_credentials(
        block_version,
        Amount::new(300_000, token2),
        &bob,
        &fog_resolver,
        &mut rng,
    );

    let mut builder = TransactionBuilder::new(
        block_version,
        Amount::new(Mob::MINIMUM_FEE, Mob::ID),
        fog_resolver,
        EmptyMemoBuilder::default(),
    )
    .unwrap();

    // Bob supplies his (excess) token id 2
    builder.add_input(input_credentials);

    // Bob adds the presigned input, which also adds the required outputs
    sci.tx_in.proofs = proofs;
    builder.add_presigned_input(sci).unwrap();

    let bob_change_dest = ReservedSubaddresses::from(&bob);

    // Bob keeps the change from token id 2
    builder
        .add_change_output(Amount::new(200_000, token2), &bob_change_dest, &mut rng)
        .unwrap();

    // Bob sends the Mob that Alice supplies, less fees, to his friend Charlie
    builder
        .add_output(
            Amount::new(value - Mob::MINIMUM_FEE, Mob::ID),
            &charlie.default_subaddress(),
            &mut rng,
        )
        .unwrap();

    let unsigned_tx = builder
        .build_unsigned::<DefaultTxOutputsOrdering>()
        .unwrap();

    let (signing_data, tx_summary, tx_summary_unblinding_data, extended_message_digest) =
        unsigned_tx.get_signing_data(&mut rng).unwrap();

    let (mlsag_signing_digest, report) = verify_tx_summary(
        &extended_message_digest.0.try_into().unwrap(),
        &tx_summary,
        &tx_summary_unblinding_data,
        *bob.view_private_key(),
        bob.change_subaddress(),
    )
    .unwrap();
    assert_eq!(
        &mlsag_signing_digest[..],
        &signing_data.mlsag_signing_digest[..]
    );

    let charlie_hash = ShortAddressHash::from(&charlie.default_subaddress());

    assert_eq!(
        &report.totals,
        &[
            // Bob's spend to create the transaction
            (token2, value2 as i64),
        ]
    );
    let mut outputs = vec![
        // Converted output to charlie, - fee paid from Mob input
        (
            TransactionEntity::OtherAddress(charlie_hash),
            Mob::ID,
            (value - Mob::MINIMUM_FEE),
        ),
        // Output to swap counterparty
        (TransactionEntity::Swap, token2, value2),
    ];
    outputs.sort();
    assert_eq!(&report.outputs[..], &outputs[..]);

    assert_eq!(report.network_fee, Amount::new(Mob::MINIMUM_FEE, Mob::ID));
}
