// Copyright (c) 2018-2022 The MobileCoin Foundation

mod util;

use assert_matches::assert_matches;
use mc_account_keys::AccountKey;
use mc_crypto_keys::RistrettoPublic;
use mc_transaction_core::{
    get_tx_out_shared_secret, tx::Tx, Amount, BlockVersion, InputRuleError, InputRules,
    MaskedAmount, MaskedAmountV2, RevealedTxOut, RevealedTxOutError,
};
use mc_transaction_std::DefaultTxOutputsOrdering;
use mc_util_from_random::FromRandom;
use mc_util_test_helper::{RngType, SeedableRng};

use util::{
    create_test_tx, create_test_tx_with_amount_and_comparer_and_recipients,
    INITIALIZE_LEDGER_AMOUNT,
};

// Gets the set of rules from the first input of a Tx
fn get_first_rules(tx: &Tx) -> &InputRules {
    tx.prefix.inputs[0].input_rules.as_ref().unwrap()
}

// Gets the set of rules from the first input of a Tx, mutably
fn get_first_rules_mut(tx: &mut Tx) -> &mut InputRules {
    tx.prefix.inputs[0].input_rules.as_mut().unwrap()
}

// Test that input rules verification is working for required output rules
#[test]
fn test_input_rules_verify_required_outputs() {
    let block_version = BlockVersion::THREE;

    let (mut tx, _ledger) = create_test_tx(block_version);

    // Modify the Tx to have some (empty) input rules.
    // (This invalidates the signature, but we aren't checking that here)
    tx.prefix.inputs[0].input_rules = Some(InputRules::default());

    // Check that the Tx is following input rules (vacuously)
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Declare the first tx out as a required output
    let first_tx_out = tx.prefix.outputs[0].clone();
    get_first_rules_mut(&mut tx)
        .required_outputs
        .push(first_tx_out);

    // Check that the Tx is following input rules (vacuously)
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Modify the input rules to refer to a non-existent tx out
    *get_first_rules_mut(&mut tx).required_outputs[0]
        .get_masked_amount_mut()
        .unwrap()
        .get_masked_value_mut() += 1;

    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::MissingRequiredOutput)
    );
}

// Test that input rules verification is working for max tombstone block rules
#[test]
fn test_input_rules_verify_max_tombstone() {
    let block_version = BlockVersion::THREE;

    let (mut tx, _ledger) = create_test_tx(block_version);

    // Modify the Tx to have some (empty) input rules.
    // (This invalidates the signature, but we aren't checking that here)
    tx.prefix.inputs[0].input_rules = Some(InputRules::default());

    // Check that the Tx is following input rules (vacuously)
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Declare the tombstone block limit to be one less than the current value.
    get_first_rules_mut(&mut tx).max_tombstone_block = tx.prefix.tombstone_block - 1;

    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::MaxTombstoneBlockExceeded)
    );

    // Set the tombstone block limit to be more permissive, now everything should be
    // good
    get_first_rules_mut(&mut tx).max_tombstone_block = tx.prefix.tombstone_block + 1;

    get_first_rules(&tx).verify(block_version, &tx).unwrap();
}

fn change_committed_amount(r_txo: &RevealedTxOut, new_amount: Amount) -> RevealedTxOut {
    // Confirm that this can even be revealed
    r_txo.reveal_amount().unwrap();

    let mut result = r_txo.clone();
    let new_masked_amount = MaskedAmountV2::new_from_amount_shared_secret(
        new_amount,
        &r_txo.amount_shared_secret[..].try_into().unwrap(),
    )
    .unwrap();

    // Confirm that the new masked amount can be decoded using this shared secret as
    // expected
    assert_eq!(
        new_amount,
        new_masked_amount
            .get_value_from_amount_shared_secret(
                &r_txo.amount_shared_secret[..].try_into().unwrap()
            )
            .unwrap()
            .0
    );

    result.tx_out.masked_amount = Some(MaskedAmount::V2(new_masked_amount));
    result
}

// Get a tx with four outputs each worth 1000, and add (empty) input rules to
// it, which we can modify to test the input rule verification code
//
// Returns the Tx, and a list of RevealedTxOut corresponding to its four
// outputs.
fn get_input_rules_test_tx(block_version: BlockVersion) -> (Tx, Vec<RevealedTxOut>) {
    let mut rng: RngType = SeedableRng::from_seed([7u8; 32]);
    let alice = AccountKey::random(&mut rng);
    let alice_pub = alice.default_subaddress();
    // Amount is 4000, so we will create 4 tx outs worth 1000
    let (mut tx, _ledger) =
        create_test_tx_with_amount_and_comparer_and_recipients::<DefaultTxOutputsOrdering>(
            block_version,
            4000,
            INITIALIZE_LEDGER_AMOUNT - 4000,
            &[&alice_pub, &alice_pub, &alice_pub, &alice_pub],
        );

    // Modify the Tx to have some (empty) input rules.
    // (This invalidates the signature, but we aren't checking that here)
    tx.prefix.inputs[0].input_rules = Some(InputRules::default());

    // Check that the Tx is following input rules (vacuously)
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // We're going to pull the four TxOut's from the TxPrefix, and make
    // corresponding fractional outputs and fractional change from them, also
    // rewriting their amounts when we do that, to see what happens to the
    // validation routine. In order to do that, we need to get their amount
    // shared secrets, and since Alice is the owner, we need Alice's
    // account keys to do that.
    assert_eq!(tx.prefix.outputs.len(), 4);
    assert!(tx.prefix.outputs[0].public_key != tx.prefix.outputs[1].public_key);
    let revealed_tx_outs: Vec<RevealedTxOut> = tx
        .prefix
        .outputs
        .iter()
        .map(|txo| {
            let decompressed_tx_pub = RistrettoPublic::try_from(&txo.public_key).unwrap();
            let tx_out_shared_secret =
                get_tx_out_shared_secret(alice.view_private_key(), &decompressed_tx_pub);
            let amount_shared_secret =
                MaskedAmount::compute_amount_shared_secret(block_version, &tx_out_shared_secret)
                    .unwrap();
            let (amount, _) = txo
                .masked_amount
                .as_ref()
                .unwrap()
                .get_value_from_amount_shared_secret(&amount_shared_secret)
                .unwrap();
            assert_eq!(amount.value, 1000);
            assert_eq!(*amount.token_id, 0);
            RevealedTxOut {
                tx_out: txo.clone(),
                amount_shared_secret: amount_shared_secret.to_vec(),
            }
        })
        .collect();
    (tx, revealed_tx_outs)
}

// Test that min_partial_fill_value is working as expected
#[test]
fn test_input_rules_verify_min_partial_fill_value() {
    let block_version = BlockVersion::THREE;
    let (mut tx, revealed_tx_outs) = get_input_rules_test_tx(block_version);

    // Try setting min_partial_fil_value without any other factional rules
    // This should be an error
    get_first_rules_mut(&mut tx).min_partial_fill_value = 1;
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::MinPartialFillValueNotExpected)
    );
    // Set it back, we should be good again.
    get_first_rules_mut(&mut tx).min_partial_fill_value = 0;
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Add a partial fill output, by doubling one of the revealed tx outs.
    // So this means we are filling the 1/2 of the request.
    // Before we add a partial fill change output, this is ill-formed.
    get_first_rules_mut(&mut tx)
        .partial_fill_outputs
        .push(change_committed_amount(
            &revealed_tx_outs[1],
            Amount::new(2000, 0.into()),
        ));
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::PartialFillOutputsNotExpected)
    );

    // Add a partial fill change, also by doubling one of the revealed tx outs.
    // This means the fill fraction is 1/2, which we are satisfying.
    get_first_rules_mut(&mut tx).partial_fill_change = Some(change_committed_amount(
        &revealed_tx_outs[0],
        Amount::new(2000, 0.into()),
    ));
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Lets try imposing a min fil
    // This is <= 1000 so we should still be valid.
    get_first_rules_mut(&mut tx).min_partial_fill_value = 1000;
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Lets try imposing a higher minimum that should cause things to fail
    get_first_rules_mut(&mut tx).min_partial_fill_value = 1001;
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::FractionalChangeOutputAmountExceedsLimit)
    );
}

// Test that partial fill outputs and change without matching real outputs cause
// invalid transactions
#[test]
fn test_input_rules_verify_missing_real_outputs() {
    let block_version = BlockVersion::THREE;
    let mut rng: RngType = SeedableRng::from_seed([7u8; 32]);
    let (mut tx, revealed_tx_outs) = get_input_rules_test_tx(block_version);
    get_first_rules_mut(&mut tx)
        .partial_fill_outputs
        .push(change_committed_amount(
            &revealed_tx_outs[1],
            Amount::new(2000, 0.into()),
        ));
    get_first_rules_mut(&mut tx).partial_fill_change = Some(change_committed_amount(
        &revealed_tx_outs[0],
        Amount::new(2000, 0.into()),
    ));
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Change that partial fill output to 2000, so everything should be good again.
    get_first_rules_mut(&mut tx)
        .partial_fill_outputs
        .push(change_committed_amount(
            &revealed_tx_outs[3],
            Amount::new(2000, 0.into()),
        ));
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Modify the input rules to refer to a non-existent tx out among the partial fill
    // outputs
    get_first_rules_mut(&mut tx).partial_fill_outputs[1]
        .tx_out
        .target_key = RistrettoPublic::from_random(&mut rng).into();
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::MissingFractionalOutput)
    );

    // Change it back to another value that should still be okay
    get_first_rules_mut(&mut tx).partial_fill_outputs[1] =
        change_committed_amount(&revealed_tx_outs[3], Amount::new(1500, 0.into()));
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Modify the input rules to refer to a non-existent tx out for the partial fill
    // change
    get_first_rules_mut(&mut tx)
        .partial_fill_change
        .as_mut()
        .unwrap()
        .tx_out
        .public_key = RistrettoPublic::from_random(&mut rng).into();
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::MissingFractionalChangeOutput)
    );

    // Change it back to another value that should be okay
    get_first_rules_mut(&mut tx).partial_fill_change = Some(change_committed_amount(
        &revealed_tx_outs[2],
        Amount::new(1500, 0.into()),
    ));
    get_first_rules(&tx).verify(block_version, &tx).unwrap();
}

// Test that invalid amount shared secrets cause invalid transactions
#[test]
fn test_input_rules_verify_invalid_amount_shared_secret() {
    let block_version = BlockVersion::THREE;
    let (mut tx, revealed_tx_outs) = get_input_rules_test_tx(block_version);
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Add a partial fill output, by doubling one of the revealed tx outs.
    get_first_rules_mut(&mut tx)
        .partial_fill_outputs
        .push(change_committed_amount(
            &revealed_tx_outs[1],
            Amount::new(2000, 0.into()),
        ));
    // Add a parital fill change, also by doubling one of the revealed tx outs.
    // This means the fill fraction is 1/2, which we are satisfying.
    get_first_rules_mut(&mut tx).partial_fill_change = Some(change_committed_amount(
        &revealed_tx_outs[0],
        Amount::new(2000, 0.into()),
    ));
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Change the partial fill change value so that the amount shared secret doesn't
    // match what is recorded
    let amount_shared_secret = [9u8; 32];
    get_first_rules_mut(&mut tx)
        .partial_fill_change
        .as_mut()
        .unwrap()
        .tx_out
        .masked_amount = Some(
        MaskedAmount::new_from_amount_shared_secret(
            block_version,
            Amount::new(2000, 0.into()),
            &amount_shared_secret,
        )
        .unwrap(),
    );
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::RevealedTxOut(RevealedTxOutError::Amount(_)))
    );

    // Now the amount shared secret matches what is recorded, but it doesn't match
    // the real change output
    get_first_rules_mut(&mut tx)
        .partial_fill_change
        .as_mut()
        .unwrap()
        .amount_shared_secret = amount_shared_secret.to_vec();
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::RevealedTxOut(RevealedTxOutError::Amount(_)))
    );

    // Now the amount shared secret is the wrong size
    get_first_rules_mut(&mut tx)
        .partial_fill_change
        .as_mut()
        .unwrap()
        .amount_shared_secret = Default::default();
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::RevealedTxOut(
            RevealedTxOutError::InvalidAmountSharedSecret
        ))
    );
}

// Test that input rules verification is working for a Tx with partial fill outputs
// and various fill fractions
#[test]
fn test_input_rules_verify_partial_fill_outputs() {
    let block_version = BlockVersion::THREE;
    let (mut tx, revealed_tx_outs) = get_input_rules_test_tx(block_version);

    // Add a partial fill output, by tripling one of the revealed tx outs.
    // So this means we are filling the 1/3 of the request.
    get_first_rules_mut(&mut tx)
        .partial_fill_outputs
        .push(change_committed_amount(
            &revealed_tx_outs[1],
            Amount::new(3000, 0.into()),
        ));

    // Set the partial fill change output to be 1500. This means the implied fill
    // fraction is now 1/3. This should be valid.
    get_first_rules_mut(&mut tx).partial_fill_change = Some(change_committed_amount(
        &revealed_tx_outs[0],
        Amount::new(1500, 0.into()),
    ));
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Try changing the partial fill output to be 3001, so the sender requested
    // slightly more than 1/3. The tx should now be invalid.
    get_first_rules_mut(&mut tx).partial_fill_outputs[0] =
        change_committed_amount(&revealed_tx_outs[1], Amount::new(3001, 0.into()));

    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::FractionalOutputAmountDoesNotRespectFillFraction)
    );

    // Make partial fill change slightly more, at 1501, so the counterparty gave back slightly less than 2/3.
    get_first_rules_mut(&mut tx).partial_fill_change = Some(change_committed_amount(
        &revealed_tx_outs[0],
        Amount::new(1501, 0.into()),
    ));
    // Set the partial fill output to be 3000 again. This should now be invalid
    get_first_rules_mut(&mut tx).partial_fill_outputs[0] =
        change_committed_amount(&revealed_tx_outs[1], Amount::new(3000, 0.into()));
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::FractionalOutputAmountDoesNotRespectFillFraction)
    );
    // Set the partial fill output to be 2997. This should still be invalid but on the
    // boundary
    get_first_rules_mut(&mut tx).partial_fill_outputs[0] =
        change_committed_amount(&revealed_tx_outs[1], Amount::new(2997, 0.into()));
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::FractionalOutputAmountDoesNotRespectFillFraction)
    );
    // Set the partial fill output to be 2996. This should be valid again.
    get_first_rules_mut(&mut tx).partial_fill_outputs[0] =
        change_committed_amount(&revealed_tx_outs[1], Amount::new(2996, 0.into()));
    get_first_rules(&tx).verify(block_version, &tx).unwrap();
}

// Test that input rules verification is working for Tx with multiple partial fill
// outputs
#[test]
fn test_input_rules_verify_multiple_partial_fill_outputs() {
    let block_version = BlockVersion::THREE;
    let (mut tx, revealed_tx_outs) = get_input_rules_test_tx(block_version);

    // Add a partial fill output, by doubling one of the revealed tx outs.
    get_first_rules_mut(&mut tx)
        .partial_fill_outputs
        .push(change_committed_amount(
            &revealed_tx_outs[1],
            Amount::new(2000, 0.into()),
        ));
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::PartialFillOutputsNotExpected)
    );

    // Set the partial fill change output to be 3000. This means the implied fill
    // fraction is now 2/3, since the real change output only returns
    // 1/3 of this. The tx should then be invalid because we are only filling 1/2 of
    // the partial fill output that was required and not 2/3 of it.
    get_first_rules_mut(&mut tx).partial_fill_change = Some(change_committed_amount(
        &revealed_tx_outs[0],
        Amount::new(3000, 0.into()),
    ));
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::FractionalOutputAmountDoesNotRespectFillFraction)
    );

    // Change the partial fill change output to be 500. This is less than the real
    // change output value, so that should be an error.
    get_first_rules_mut(&mut tx).partial_fill_change = Some(change_committed_amount(
        &revealed_tx_outs[0],
        Amount::new(500, 0.into()),
    ));
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::FractionalChangeOutputAmountExceedsLimit)
    );

    // Change the partial fill change output to be 1500. This means the implied fill
    // fraction is now 1/3, since the real change output returns 2/3 of this.
    // The tx should then be valid again.
    get_first_rules_mut(&mut tx).partial_fill_change = Some(change_committed_amount(
        &revealed_tx_outs[0],
        Amount::new(1500, 0.into()),
    ));
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Add another partial fill output at 3000. Since fill fraction is 1/3 this is
    // still a valid tx.
    get_first_rules_mut(&mut tx)
        .partial_fill_outputs
        .push(change_committed_amount(
            &revealed_tx_outs[3],
            Amount::new(3000, 0.into()),
        ));
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Change the partial fill change so that the fill fraction is 1/2 again. This
    // should now be invalid again because the latest output is only 1/3 filled.
    get_first_rules_mut(&mut tx).partial_fill_change = Some(change_committed_amount(
        &revealed_tx_outs[0],
        Amount::new(2000, 0.into()),
    ));
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::FractionalOutputAmountDoesNotRespectFillFraction)
    );
}

// Test that input rules verification is working for Tx with a mix of required
// and partial fill outputs
#[test]
fn test_input_rules_verify_mixed_required_and_partial_fill_outputs() {
    let block_version = BlockVersion::THREE;
    let (mut tx, revealed_tx_outs) = get_input_rules_test_tx(block_version);

    // Set the partial fill change output to be 1200, so fill fraction is 1/6
    get_first_rules_mut(&mut tx).partial_fill_change = Some(change_committed_amount(
        &revealed_tx_outs[0],
        Amount::new(1200, 0.into()),
    ));

    // Add a partial fill output, by going to 6x the revealed tx out
    get_first_rules_mut(&mut tx)
        .partial_fill_outputs
        .push(change_committed_amount(
            &revealed_tx_outs[1],
            Amount::new(6000, 0.into()),
        ));

    // Everything should be okay right now
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Add a required output, using the last tx out
    get_first_rules_mut(&mut tx)
        .required_outputs
        .push(revealed_tx_outs[3].tx_out.clone());

    // Everything should be okay right now
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Try changing the partial fill output by increasing the ask slightly, the Tx
    // should be invalid
    get_first_rules_mut(&mut tx).partial_fill_outputs[0] =
        change_committed_amount(&revealed_tx_outs[1], Amount::new(6001, 0.into()));
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::FractionalOutputAmountDoesNotRespectFillFraction)
    );

    // Reduce partial fill change offer slightly, things should be okay now
    get_first_rules_mut(&mut tx).partial_fill_change = Some(change_committed_amount(
        &revealed_tx_outs[0],
        Amount::new(1199, 0.into()),
    ));
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Things should still be okay on the ask up to 6025, but bad at 6026
    get_first_rules_mut(&mut tx).partial_fill_outputs[0] =
        change_committed_amount(&revealed_tx_outs[1], Amount::new(6026, 0.into()));
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::FractionalOutputAmountDoesNotRespectFillFraction)
    );
    get_first_rules_mut(&mut tx).partial_fill_outputs[0] =
        change_committed_amount(&revealed_tx_outs[1], Amount::new(6025, 0.into()));
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Try tweaking the required output
    get_first_rules_mut(&mut tx).required_outputs[0] =
        change_committed_amount(&revealed_tx_outs[3], Amount::new(987, 0.into())).tx_out;
    assert_matches!(
        get_first_rules(&tx).verify(block_version, &tx),
        Err(InputRuleError::MissingRequiredOutput)
    );

    // Change the output in the tx prefix to match
    tx.prefix.outputs[3] =
        change_committed_amount(&revealed_tx_outs[3], Amount::new(987, 0.into())).tx_out;
    // Should now all be okay
    get_first_rules(&tx).verify(block_version, &tx).unwrap();
}
