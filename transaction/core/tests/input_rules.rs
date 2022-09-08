// Copyright (c) 2018-2022 The MobileCoin Foundation

mod util;

use mc_transaction_core::{tx::Tx, BlockVersion, InputRules};

use util::create_test_tx;

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
    tx.prefix.inputs[0].input_rules = Some(InputRules {
        required_outputs: vec![],
        max_tombstone_block: 0,
    });

    // Check that the Tx is following input rules (vacuously)
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Modify the Tx to have some input rules.
    // (This invalidates the signature, but we aren't checking that here)
    let first_tx_out = tx.prefix.outputs[0].clone();

    // Declare the first tx out as a required output
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
    tx.prefix.inputs[0].input_rules = Some(InputRules {
        required_outputs: vec![],
        max_tombstone_block: 0,
    });

    // Check that the Tx is following input rules (vacuously)
    get_first_rules(&tx).verify(block_version, &tx).unwrap();

    // Declare the tombstone block limit to be one less than the current value.
    tx.prefix.inputs[0].input_rules = Some(InputRules {
        required_outputs: vec![],
        max_tombstone_block: tx.prefix.tombstone_block - 1,
    });

    assert!(get_first_rules(&tx).verify(block_version, &tx).is_err());

    // Set the tombstone block limit to be more permissive, now everything should be
    // good
    get_first_rules_mut(&mut tx).max_tombstone_block = tx.prefix.tombstone_block + 1;

    get_first_rules(&tx).verify(block_version, &tx).unwrap();
}
