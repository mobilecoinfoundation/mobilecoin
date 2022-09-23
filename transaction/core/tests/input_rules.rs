// Copyright (c) 2018-2022 The MobileCoin Foundation

mod util;

use mc_account_keys::{AccountKey};
use mc_crypto_keys::{RistrettoPublic};
use mc_transaction_core::{tx::Tx, BlockVersion, InputRules, RevealedTxOut, Amount, MaskedAmount, MaskedAmountV2, get_tx_out_shared_secret};
use mc_transaction_std::DefaultTxOutputsOrdering;
use mc_util_from_random::FromRandom;
use mc_util_test_helper::{SeedableRng, RngType};

use util::{create_test_tx, create_test_tx_with_amount_and_comparer_and_recipients};

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

    assert!(get_first_rules(&tx).verify(block_version, &tx).is_err());
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

    assert!(get_first_rules(&tx).verify(block_version, &tx).is_err());

    // Set the tombstone block limit to be more permissive, now everything should be
    // good
    get_first_rules_mut(&mut tx).max_tombstone_block = tx.prefix.tombstone_block + 1;

    get_first_rules(&tx).verify(block_version, &tx).unwrap();
}

fn change_committed_amount(r_txo: &RevealedTxOut, new_amount: Amount) -> RevealedTxOut {
    // Confirm that this can even be revealed
    r_txo.reveal_amount().unwrap();

    let mut result = r_txo.clone();
    let new_masked_amount = MaskedAmountV2::new_from_amount_shared_secret(new_amount, &r_txo.amount_shared_secret[..].try_into().unwrap()).unwrap();

    // Confirm that the new masked amount can be decoded using this shared secret as expected
    assert_eq!(new_amount, new_masked_amount.get_value_from_amount_shared_secret(&r_txo.amount_shared_secret[..].try_into().unwrap()).unwrap().0);
    
    result.tx_out.masked_amount = Some(MaskedAmount::V2(new_masked_amount));
    result
}

// Test that input rules verification is working for fractional output rules
#[test]
fn test_input_rules_verify_fractional_outputs() {
    let block_version = BlockVersion::THREE;

    let mut rng: RngType = SeedableRng::from_seed([7u8; 32]);
    let alice = AccountKey::random(&mut rng);
    let alice_pub = alice.default_subaddress();
    // Amount is 1000, so we will create 4 tx outs worth 250
    let (mut tx, _ledger) = create_test_tx_with_amount_and_comparer_and_recipients::<DefaultTxOutputsOrdering>(block_version, 1000, &[&alice_pub, &alice_pub, &alice_pub, &alice_pub]);

    // Modify the Tx to have some (empty) input rules.
    // (This invalidates the signature, but we aren't checking that here)
    tx.prefix.inputs[0].input_rules = Some(InputRules::default());

    // Check that the Tx is following input rules (vacuously)
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // We're going to pull the three TxOut's from the TxPrefix, and make corresponding fractional outputs and fractional change
    // from them, also rewriting their amounts when we do that, to see what happens to the validation routine.
    // In order to do that, we need to get their amount shared secrets, and since Alice is the owner, we need Alice's
    // account keys to do that.
    assert_eq!(tx.prefix.outputs.len(), 4);
    assert!(tx.prefix.outputs[0].public_key != tx.prefix.outputs[1].public_key);
    let revealed_tx_outs: Vec<RevealedTxOut> = tx.prefix.outputs.iter().map(|txo| {
        let decompressed_tx_pub = RistrettoPublic::try_from(&txo.public_key).unwrap();
        let tx_out_shared_secret = get_tx_out_shared_secret(alice.view_private_key(), &decompressed_tx_pub);
        let amount_shared_secret = MaskedAmountV2::compute_amount_shared_secret(&tx_out_shared_secret);
        let (amount, _) = txo.masked_amount.as_ref().unwrap().get_value_from_amount_shared_secret(&amount_shared_secret).unwrap();
        assert_eq!(amount.value, 250);
        assert_eq!(*amount.token_id, 0);
        RevealedTxOut {
            tx_out: txo.clone(),
            amount_shared_secret: amount_shared_secret.to_vec(),
        }
    }).collect();

    // Add a fractional input and output, by doubling the revealed tx outs.
    // This means the fill fraction is 1/2.
    get_first_rules_mut(&mut tx).fractional_change = Some(change_committed_amount(&revealed_tx_outs[0], Amount::new(500, 0.into())));
    get_first_rules_mut(&mut tx).fractional_outputs.push(change_committed_amount(&revealed_tx_outs[1], Amount::new(500, 0.into())));
    
    // Check that the Tx is following input rules
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Lets try imposing a limit on the change value
    // This is larger than 1000 so we should still be valid.
    get_first_rules_mut(&mut tx).max_allowed_change_value = 260;
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Lets try imposing a smaller limit that should cause things to fail
    get_first_rules_mut(&mut tx).max_allowed_change_value = 240;
    assert!(get_first_rules(&tx).verify(block_version, &tx).is_err());

    // Remove limit altogether, we should be valid again
    get_first_rules_mut(&mut tx).max_allowed_change_value = 0;
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Change the frational change output to be 3000. This means the implied fill fraction is now 2/3, since the real change output only returns
    // 1/3 of this. The tx should then be invalid because we are only filling 1/2 of the fractional output that was required and not 2/3 of it.
    get_first_rules_mut(&mut tx).fractional_change = Some(change_committed_amount(&revealed_tx_outs[0], Amount::new(750, 0.into())));
    assert!(get_first_rules(&tx).verify(block_version, &tx).is_err());

    // Change the frational change output to be 1500. This means the implied fill fraction is now 1/3, since the real change output returns
    // 2/3 of this. The tx should then be valid again.
    get_first_rules_mut(&mut tx).fractional_change = Some(change_committed_amount(&revealed_tx_outs[0], Amount::new(375, 0.into())));    
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Add another fractional output at 3000. Since fill fraction is 1/3 this is still a valid tx.
    get_first_rules_mut(&mut tx).fractional_outputs.push(change_committed_amount(&revealed_tx_outs[3], Amount::new(750, 0.into())));
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Change the fractional change so that the fill fraction is 1/2 again. This should now be invalid again because the latest ouptut is only 1/3 filled.
    get_first_rules_mut(&mut tx).fractional_change = Some(change_committed_amount(&revealed_tx_outs[0], Amount::new(500, 0.into())));
    assert!(get_first_rules(&tx).verify(block_version, &tx).is_err());

    // Change that fractional output to 2000, so everything should be good again.
    get_first_rules_mut(&mut tx).fractional_outputs[1] = change_committed_amount(&revealed_tx_outs[3], Amount::new(500, 0.into()));
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Modify the input rules to refer to a non-existent tx out among the fractional outputs
    get_first_rules_mut(&mut tx).fractional_outputs[1]
        .tx_out.target_key = RistrettoPublic::from_random(&mut rng).into();
    assert!(get_first_rules(&tx).verify(block_version, &tx).is_err());

    // Change it back to another value that should still be okay
    get_first_rules_mut(&mut tx).fractional_outputs[1] = change_committed_amount(&revealed_tx_outs[3], Amount::new(375, 0.into()));
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Modify the input rules to refer to a non-existent tx out for the fractional change
    get_first_rules_mut(&mut tx).fractional_change.as_mut().unwrap()
        .tx_out.public_key = RistrettoPublic::from_random(&mut rng).into();
    assert!(get_first_rules(&tx).verify(block_version, &tx).is_err());
}
