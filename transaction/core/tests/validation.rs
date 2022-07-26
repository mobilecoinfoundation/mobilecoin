// Copyright (c) 2018-2022 The MobileCoin Foundation

//! This module is meant to unit test all of the functionality in the validation
//! module in mc-transaction-core.

extern crate alloc;

mod util;

use crate::util::{
    create_test_tx, create_test_tx_with_amount,
    create_test_tx_with_amount_and_comparer_and_recipients,
};
use alloc::vec::Vec;
use mc_account_keys::AccountKey;
use mc_crypto_keys::{CompressedRistrettoPublic, ReprBytes};
use mc_ledger_db::{
    test_utils::{InverseTxOutputsOrdering, INITIALIZE_LEDGER_AMOUNT},
    Ledger,
};
use mc_transaction_core::{
    constants::{MAX_TOMBSTONE_BLOCKS, RING_SIZE},
    membership_proofs::Range,
    tokens::Mob,
    tx::{TxOutMembershipHash, TxOutMembershipProof},
    validation::*,
    BlockVersion, InputRules, Token,
};
use mc_util_test_helper::get_seeded_rng;

#[test]
// Should return MissingMemo when memos are missing in an output
fn test_validate_memo_exists() {
    let (tx, _) = create_test_tx(BlockVersion::ZERO);
    let tx_out = tx.prefix.outputs.first().unwrap();

    assert!(tx_out.e_memo.is_none());
    assert_eq!(
        validate_memo_exists(tx_out),
        Err(TransactionValidationError::MissingMemo)
    );

    let (tx, _) = create_test_tx(BlockVersion::ONE);
    let tx_out = tx.prefix.outputs.first().unwrap();

    assert!(tx_out.e_memo.is_some());
    assert_eq!(validate_memo_exists(tx_out), Ok(()));
}

#[test]
// Should return MemosNotAllowed when memos are present in an output
fn test_validate_that_no_memo_exists() {
    let (tx, _) = create_test_tx(BlockVersion::ZERO);
    let tx_out = tx.prefix.outputs.first().unwrap();

    assert!(tx_out.e_memo.is_none());
    assert_eq!(validate_that_no_memo_exists(tx_out), Ok(()));

    let (tx, _) = create_test_tx(BlockVersion::ONE);
    let tx_out = tx.prefix.outputs.first().unwrap();

    assert!(tx_out.e_memo.is_some());
    assert_eq!(
        validate_that_no_memo_exists(tx_out),
        Err(TransactionValidationError::MemosNotAllowed)
    );
}

#[test]
// Should return MissingMaskedTokenId when masked_token_id are missing in an
// output
fn test_validate_masked_token_id_exists() {
    let (tx, _) = create_test_tx(BlockVersion::ONE);
    let tx_out = tx.prefix.outputs.first().unwrap();

    assert!(tx_out.masked_amount.masked_token_id.is_empty());
    assert_eq!(
        validate_masked_token_id_exists(tx_out),
        Err(TransactionValidationError::MissingMaskedTokenId)
    );

    let (tx, _) = create_test_tx(BlockVersion::TWO);
    let tx_out = tx.prefix.outputs.first().unwrap();

    assert!(!tx_out.masked_amount.masked_token_id.is_empty());
    assert_eq!(validate_memo_exists(tx_out), Ok(()));
}

#[test]
// Should return MemosNotAllowed when memos are present in an output
fn test_validate_no_masked_token_id_exists() {
    let (tx, _) = create_test_tx(BlockVersion::ONE);
    let tx_out = tx.prefix.outputs.first().unwrap();

    assert!(tx_out.masked_amount.masked_token_id.is_empty());
    assert_eq!(validate_that_no_masked_token_id_exists(tx_out), Ok(()));

    let (tx, _) = create_test_tx(BlockVersion::TWO);
    let tx_out = tx.prefix.outputs.first().unwrap();

    assert!(!tx_out.masked_amount.masked_token_id.is_empty());
    assert_eq!(
        validate_that_no_masked_token_id_exists(tx_out),
        Err(TransactionValidationError::MaskedTokenIdNotAllowed)
    );
}

#[test]
// Should return Ok(()) when the Tx's membership proofs are correct and agree
// with ledger.
fn test_validate_membership_proofs() {
    for block_version in BlockVersion::iterator() {
        let (tx, ledger) = create_test_tx(block_version);

        let highest_indices = tx.get_membership_proof_highest_indices();
        let root_proofs: Vec<TxOutMembershipProof> = ledger
            .get_tx_out_proof_of_memberships(&highest_indices)
            .expect("failed getting proofs");

        // Validate the transaction prefix without providing the correct ledger context.
        {
            let mut broken_proofs = root_proofs.clone();
            broken_proofs[0].elements[0].hash = TxOutMembershipHash::from([1u8; 32]);
            assert_eq!(
                validate_membership_proofs(&tx.prefix, &broken_proofs),
                Err(TransactionValidationError::InvalidTxOutMembershipProof)
            );
        }

        // Validate the transaction prefix with the correct root proofs.
        {
            let highest_indices = tx.get_membership_proof_highest_indices();
            let root_proofs: Vec<TxOutMembershipProof> = ledger
                .get_tx_out_proof_of_memberships(&highest_indices)
                .expect("failed getting proofs");
            assert_eq!(validate_membership_proofs(&tx.prefix, &root_proofs), Ok(()));
        }
    }
}

#[test]
// Should return InvalidRangeProof if a membership proof containing an invalid
// Range.
fn test_validate_membership_proofs_invalid_range_in_tx() {
    for block_version in BlockVersion::iterator() {
        let (mut tx, ledger) = create_test_tx(block_version);

        let highest_indices = tx.get_membership_proof_highest_indices();
        let root_proofs: Vec<TxOutMembershipProof> = ledger
            .get_tx_out_proof_of_memberships(&highest_indices)
            .expect("failed getting proofs");

        // Modify tx to include an invalid Range.
        let mut proof = tx.prefix.inputs[0].proofs[0].clone();
        let mut first_element = proof.elements[0].clone();
        first_element.range = Range { from: 7, to: 3 };
        proof.elements[0] = first_element;
        tx.prefix.inputs[0].proofs[0] = proof;

        assert_eq!(
            validate_membership_proofs(&tx.prefix, &root_proofs),
            Err(TransactionValidationError::MembershipProofValidationError)
        );
    }
}

#[test]
// Should return InvalidRangeProof if a root proof containing an invalid Range.
fn test_validate_membership_proofs_invalid_range_in_root_proof() {
    for block_version in BlockVersion::iterator() {
        let (tx, ledger) = create_test_tx(block_version);

        let highest_indices = tx.get_membership_proof_highest_indices();
        let mut root_proofs: Vec<TxOutMembershipProof> = ledger
            .get_tx_out_proof_of_memberships(&highest_indices)
            .expect("failed getting proofs");

        // Modify a root proof to include an invalid Range.
        let mut proof = root_proofs[0].clone();
        let mut first_element = proof.elements[0].clone();
        first_element.range = Range { from: 7, to: 3 };
        proof.elements[0] = first_element;
        root_proofs[0] = proof;

        assert_eq!(
            validate_membership_proofs(&tx.prefix, &root_proofs),
            Err(TransactionValidationError::MembershipProofValidationError)
        );
    }
}

#[test]
// Test that validate_number_of_inputs is working as expected
fn test_validate_number_of_inputs() {
    for block_version in BlockVersion::iterator() {
        let (orig_tx, _ledger) = create_test_tx(block_version);
        let max_inputs = 25;

        for num_inputs in 0..100 {
            let mut tx_prefix = orig_tx.prefix.clone();
            tx_prefix.inputs.clear();
            for _i in 0..num_inputs {
                tx_prefix.inputs.push(orig_tx.prefix.inputs[0].clone());
            }

            let expected_result = if num_inputs == 0 {
                Err(TransactionValidationError::NoInputs)
            } else if num_inputs > max_inputs {
                Err(TransactionValidationError::TooManyInputs)
            } else {
                Ok(())
            };

            assert_eq!(
                validate_number_of_inputs(&tx_prefix, max_inputs),
                expected_result,
            );
        }
    }
}

#[test]
// Test that validate_number_of_outputs is working as expected
fn test_validate_number_of_outputs() {
    for block_version in BlockVersion::iterator() {
        let (orig_tx, _ledger) = create_test_tx(block_version);
        let max_outputs = 25;

        for num_outputs in 0..100 {
            let mut tx_prefix = orig_tx.prefix.clone();
            tx_prefix.outputs.clear();
            for _i in 0..num_outputs {
                tx_prefix.outputs.push(orig_tx.prefix.outputs[0].clone());
            }

            let expected_result = if num_outputs == 0 {
                Err(TransactionValidationError::NoOutputs)
            } else if num_outputs > max_outputs {
                Err(TransactionValidationError::TooManyOutputs)
            } else {
                Ok(())
            };

            assert_eq!(
                validate_number_of_outputs(&tx_prefix, max_outputs),
                expected_result,
            );
        }
    }
}

#[test]
// Test that validate_ring_sizes is working as expected
fn test_validate_ring_sizes() {
    for block_version in BlockVersion::iterator() {
        let (tx, _ledger) = create_test_tx(block_version);
        assert_eq!(tx.prefix.inputs.len(), 1);
        assert_eq!(tx.prefix.inputs[0].ring.len(), RING_SIZE);

        // A transaction with a single input containing RING_SIZE elements.
        assert_eq!(validate_ring_sizes(&tx.prefix, RING_SIZE), Ok(()));

        // A single input containing zero elements.
        {
            let mut tx_prefix = tx.prefix.clone();
            tx_prefix.inputs[0].ring.clear();

            assert_eq!(
                validate_ring_sizes(&tx_prefix, RING_SIZE),
                Err(TransactionValidationError::InsufficientRingSize),
            );
        }

        // A single input containing too few elements.
        {
            let mut tx_prefix = tx.prefix.clone();
            tx_prefix.inputs[0].ring.pop();

            assert_eq!(
                validate_ring_sizes(&tx_prefix, RING_SIZE),
                Err(TransactionValidationError::InsufficientRingSize),
            );
        }

        // A single input containing too many elements.
        {
            let mut tx_prefix = tx.prefix.clone();
            let element = tx_prefix.inputs[0].ring[0].clone();
            tx_prefix.inputs[0].ring.push(element);

            assert_eq!(
                validate_ring_sizes(&tx_prefix, RING_SIZE),
                Err(TransactionValidationError::ExcessiveRingSize),
            );
        }

        // Two inputs each containing RING_SIZE elements.
        {
            let mut tx_prefix = tx.prefix.clone();
            let input = tx_prefix.inputs[0].clone();
            tx_prefix.inputs.push(input);

            assert_eq!(validate_ring_sizes(&tx_prefix, RING_SIZE), Ok(()));
        }

        // The second input contains too few elements.
        {
            let mut tx_prefix = tx.prefix.clone();
            let mut input = tx_prefix.inputs[0].clone();
            input.ring.pop();
            tx_prefix.inputs.push(input);

            assert_eq!(
                validate_ring_sizes(&tx_prefix, RING_SIZE),
                Err(TransactionValidationError::InsufficientRingSize),
            );
        }
    }
}

#[test]
// Test that validate_ring_elements_are_unique is working as expected
fn test_validate_ring_elements_are_unique() {
    for block_version in BlockVersion::iterator() {
        let (tx, _ledger) = create_test_tx(block_version);
        assert_eq!(tx.prefix.inputs.len(), 1);

        // A transaction with a single input and unique ring elements.
        assert_eq!(validate_ring_elements_are_unique(&tx.prefix), Ok(()));

        // A transaction with a single input and duplicate ring elements.
        {
            let mut tx_prefix = tx.prefix.clone();
            tx_prefix.inputs[0]
                .ring
                .push(tx.prefix.inputs[0].ring[0].clone());

            assert_eq!(
                validate_ring_elements_are_unique(&tx_prefix),
                Err(TransactionValidationError::DuplicateRingElements)
            );
        }

        // A transaction with a multiple inputs and unique ring elements.
        {
            let mut tx_prefix = tx.prefix.clone();
            tx_prefix.inputs.push(tx.prefix.inputs[0].clone());

            for mut tx_out in tx_prefix.inputs[1].ring.iter_mut() {
                let mut bytes = tx_out.target_key.to_bytes();
                bytes[0] = !bytes[0];
                tx_out.target_key = CompressedRistrettoPublic::from_bytes(&bytes).unwrap();
            }

            assert_eq!(validate_ring_elements_are_unique(&tx_prefix), Ok(()));
        }

        // A transaction with a multiple inputs and duplicate ring elements in different
        // rings.
        {
            let mut tx_prefix = tx.prefix.clone();
            tx_prefix.inputs.push(tx.prefix.inputs[0].clone());

            assert_eq!(
                validate_ring_elements_are_unique(&tx_prefix),
                Err(TransactionValidationError::DuplicateRingElements)
            );
        }
    }
}

#[test]
/// validate_ring_elements_are_sorted should reject an unsorted ring.
fn test_validate_ring_elements_are_sorted() {
    for block_version in BlockVersion::iterator() {
        let (mut tx, _ledger) = create_test_tx(block_version);
        assert_eq!(validate_ring_elements_are_sorted(&tx.prefix), Ok(()));

        // Change the ordering of a ring.
        tx.prefix.inputs[0].ring.swap(0, 3);
        assert_eq!(
            validate_ring_elements_are_sorted(&tx.prefix),
            Err(TransactionValidationError::UnsortedRingElements)
        );
    }
}

#[test]
/// validate_inputs_are_sorted should reject unsorted inputs.
fn test_validate_inputs_are_sorted() {
    for block_version in BlockVersion::iterator() {
        let (tx, _ledger) = create_test_tx(block_version);

        // Add a second input to the transaction.
        let mut tx_prefix = tx.prefix.clone();
        tx_prefix.inputs.push(tx.prefix.inputs[0].clone());

        // By removing the first ring element of the second input we ensure the inputs
        // are different, but remain sorted (since the ring elements are
        // sorted).
        tx_prefix.inputs[1].ring.remove(0);

        assert_eq!(validate_inputs_are_sorted(&tx_prefix), Ok(()));

        // Change the ordering of inputs.
        tx_prefix.inputs.swap(0, 1);
        assert_eq!(
            validate_inputs_are_sorted(&tx_prefix),
            Err(TransactionValidationError::UnsortedInputs)
        );
    }
}

#[test]
/// Should reject a transaction with unsorted outputs.
fn test_validate_outputs_are_sorted() {
    for block_version in BlockVersion::iterator() {
        let (tx, _ledger) = create_test_tx(block_version);

        let mut output_a = tx.prefix.outputs.get(0).unwrap().clone();
        output_a.public_key = CompressedRistrettoPublic::from(&[1u8; 32]);

        let mut output_b = output_a.clone();
        output_b.public_key = CompressedRistrettoPublic::from(&[2u8; 32]);

        assert!(output_a.public_key < output_b.public_key);

        {
            let mut tx_prefix = tx.prefix.clone();
            // A single output is trivially sorted.
            tx_prefix.outputs = vec![output_a.clone()];
            assert_eq!(validate_outputs_are_sorted(&tx_prefix), Ok(()));
        }

        {
            let mut tx_prefix = tx.prefix.clone();
            // Outputs sorted by public_key, ascending.
            tx_prefix.outputs = vec![output_a.clone(), output_b.clone()];
            assert_eq!(validate_outputs_are_sorted(&tx_prefix), Ok(()));
        }

        {
            let mut tx_prefix = tx.prefix.clone();
            // Outputs are not correctly sorted.
            tx_prefix.outputs = vec![output_b.clone(), output_a.clone()];
            assert_eq!(
                validate_outputs_are_sorted(&tx_prefix),
                Err(TransactionValidationError::UnsortedOutputs)
            );
        }
    }
}

#[test]
/// validate_key_images_are_unique rejects duplicate key image.
fn test_validate_key_images_are_unique_rejects_duplicate() {
    for block_version in BlockVersion::iterator() {
        let (mut tx, _ledger) = create_test_tx(block_version);
        // Tx only contains a single ring signature, which contains the key image.
        // Duplicate the ring signature so that tx.key_images() returns a
        // duplicate key image.
        let ring_signature = tx.signature.ring_signatures[0].clone();
        tx.signature.ring_signatures.push(ring_signature);

        assert_eq!(
            validate_key_images_are_unique(&tx),
            Err(TransactionValidationError::DuplicateKeyImages)
        );
    }
}

#[test]
/// validate_key_images_are_unique returns Ok if all key images are unique.
fn test_validate_key_images_are_unique_ok() {
    for block_version in BlockVersion::iterator() {
        let (tx, _ledger) = create_test_tx(block_version);
        assert_eq!(validate_key_images_are_unique(&tx), Ok(()),);
    }
}

#[test]
/// validate_outputs_public_keys_are_unique rejects duplicate public key.
fn test_validate_output_public_keys_are_unique_rejects_duplicate() {
    for block_version in BlockVersion::iterator() {
        let (mut tx, _ledger) = create_test_tx(block_version);
        // Tx only contains a single output. Duplicate the
        // output so that tx.output_public_keys() returns a duplicate public key.
        let tx_out = tx.prefix.outputs[0].clone();
        tx.prefix.outputs.push(tx_out);

        assert_eq!(
            validate_outputs_public_keys_are_unique(&tx),
            Err(TransactionValidationError::DuplicateOutputPublicKey)
        );
    }
}

#[test]
/// validate_outputs_public_keys_are_unique returns Ok if all public keys
/// are unique.
fn test_validate_output_public_keys_are_unique_ok() {
    for block_version in BlockVersion::iterator() {
        let (tx, _ledger) = create_test_tx(block_version);
        assert_eq!(validate_outputs_public_keys_are_unique(&tx), Ok(()),);
    }
}

#[test]
// `validate_signature` return OK for a valid transaction.
fn test_validate_signature_ok() {
    let mut rng = get_seeded_rng();

    for block_version in BlockVersion::iterator() {
        let (tx, _ledger) = create_test_tx(block_version);
        assert_eq!(
            validate_signature(block_version, &tx, &mut rng),
            Ok(()),
            "failed at block version: {}",
            block_version
        );
    }
}

#[test]
// Should return InvalidTransactionSignature if an input is modified.
fn test_transaction_signature_err_modified_input() {
    let mut rng = get_seeded_rng();

    for block_version in BlockVersion::iterator() {
        let (mut tx, _ledger) = create_test_tx(block_version);

        // Remove an input.
        tx.prefix.inputs[0].ring.pop();

        match validate_signature(block_version, &tx, &mut rng) {
            Err(TransactionValidationError::InvalidTransactionSignature(_e)) => {} // Expected.
            Err(e) => {
                panic!("Unexpected error {}", e);
            }
            Ok(()) => panic!("Unexpected success"),
        }
    }
}

#[test]
// Should return InvalidTransactionSignature if an output is modified.
fn test_transaction_signature_err_modified_output() {
    let mut rng = get_seeded_rng();

    for block_version in BlockVersion::iterator() {
        let (mut tx, _ledger) = create_test_tx(block_version);

        // Add an output.
        let output = tx.prefix.outputs.get(0).unwrap().clone();
        tx.prefix.outputs.push(output);

        match validate_signature(block_version, &tx, &mut rng) {
            Err(TransactionValidationError::InvalidTransactionSignature(_e)) => {} // Expected.
            Err(e) => {
                panic!("Unexpected error {}", e);
            }
            Ok(()) => panic!("Unexpected success"),
        }
    }
}

#[test]
// Should return InvalidTransactionSignature if the fee is modified.
fn test_transaction_signature_err_modified_fee() {
    let mut rng = get_seeded_rng();

    for block_version in BlockVersion::iterator() {
        let (mut tx, _ledger) = create_test_tx(block_version);

        tx.prefix.fee += 1;

        match validate_signature(block_version, &tx, &mut rng) {
            Err(TransactionValidationError::InvalidTransactionSignature(_e)) => {} // Expected.
            Err(e) => {
                panic!("Unexpected error {}", e);
            }
            Ok(()) => panic!("Unexpected success"),
        }
    }
}

#[test]
// Should return InvalidTransactionSignature if the token_id is modified
fn test_transaction_signature_err_modified_token_id() {
    let mut rng = get_seeded_rng();

    for _ in 0..3 {
        let (mut tx, _ledger) = create_test_tx(BlockVersion::TWO);

        tx.prefix.fee_token_id += 1;

        match validate_signature(BlockVersion::TWO, &tx, &mut rng) {
            Err(TransactionValidationError::InvalidTransactionSignature(_e)) => {} // Expected.
            Err(e) => {
                panic!("Unexpected error {}", e);
            }
            Ok(()) => panic!("Unexpected success"),
        }
    }
}

#[test]
// Should return InvalidTransactionSignature if block v 1 is validated as 2
fn test_transaction_signature_err_version_one_as_two() {
    let mut rng = get_seeded_rng();

    for _ in 0..3 {
        let (tx, _ledger) = create_test_tx(BlockVersion::ONE);

        match validate_signature(BlockVersion::TWO, &tx, &mut rng) {
            Err(TransactionValidationError::InvalidTransactionSignature(_e)) => {} // Expected.
            Err(e) => {
                panic!("Unexpected error {}", e);
            }
            Ok(()) => panic!("Unexpected success"),
        }
    }
}

#[test]
// Should return InvalidTransactionSignature if block v 2 is validated as 1
fn test_transaction_signature_err_version_two_as_one() {
    let mut rng = get_seeded_rng();

    for _ in 0..3 {
        let (tx, _ledger) = create_test_tx(BlockVersion::TWO);

        match validate_signature(BlockVersion::ONE, &tx, &mut rng) {
            Err(TransactionValidationError::InvalidTransactionSignature(_e)) => {} // Expected.
            Err(e) => {
                panic!("Unexpected error {}", e);
            }
            Ok(()) => panic!("Unexpected success"),
        }
    }
}

#[test]
fn test_validate_transaction_fee() {
    for block_version in BlockVersion::iterator() {
        {
            // Zero fees gets rejected
            let (tx, _ledger) =
                create_test_tx_with_amount(block_version, INITIALIZE_LEDGER_AMOUNT, 0);
            assert_eq!(
                validate_transaction_fee(&tx, 1000),
                Err(TransactionValidationError::TxFeeError)
            );
        }

        {
            // Off by one fee gets rejected
            let fee = Mob::MINIMUM_FEE - 1;
            let (tx, _ledger) =
                create_test_tx_with_amount(block_version, INITIALIZE_LEDGER_AMOUNT - fee, fee);
            assert_eq!(
                validate_transaction_fee(&tx, Mob::MINIMUM_FEE),
                Err(TransactionValidationError::TxFeeError)
            );
        }

        {
            // Exact fee amount is okay
            let (tx, _ledger) = create_test_tx_with_amount(
                block_version,
                INITIALIZE_LEDGER_AMOUNT - Mob::MINIMUM_FEE,
                Mob::MINIMUM_FEE,
            );
            assert_eq!(validate_transaction_fee(&tx, Mob::MINIMUM_FEE), Ok(()));
        }

        {
            // Overpaying fees is okay
            let fee = Mob::MINIMUM_FEE + 1;
            let (tx, _ledger) =
                create_test_tx_with_amount(block_version, INITIALIZE_LEDGER_AMOUNT - fee, fee);
            assert_eq!(validate_transaction_fee(&tx, Mob::MINIMUM_FEE), Ok(()));
        }
    }
}

#[test]
/// Should return TombstoneBlockExceeded if the transaction has expired.
fn test_validate_tombstone_tombstone_block_exceeded() {
    {
        // The tombstone block is in the near future, so Ok.
        let current_block_index = 888;
        let tombstone_block_index = 889;
        assert_eq!(
            validate_tombstone(current_block_index, tombstone_block_index),
            Ok(())
        );
    }

    {
        // The tombstone block is the current block.
        let current_block_index = 7;
        let tombstone_block_index = 7;
        assert_eq!(
            validate_tombstone(current_block_index, tombstone_block_index),
            Err(TransactionValidationError::TombstoneBlockExceeded)
        );
    }

    {
        // The tombstone block is in the past.
        let current_block_index = 888;
        let tombstone_block_index = 7;
        assert_eq!(
            validate_tombstone(current_block_index, tombstone_block_index),
            Err(TransactionValidationError::TombstoneBlockExceeded)
        );
    }
}

#[test]
/// Should return TombstoneBlockTooFar if the tombstone is too far in the
/// future.
fn test_validate_tombstone_tombstone_block_too_far() {
    {
        // The tombstone block is in the near future, so Ok.
        let current_block_index = 7;
        let tombstone_block_index = current_block_index + 1;
        assert_eq!(
            validate_tombstone(current_block_index, tombstone_block_index),
            Ok(())
        );
    }

    {
        // Largest tombstone that is still Ok.
        let current_block_index = 7;
        let tombstone_block_index = current_block_index + MAX_TOMBSTONE_BLOCKS;
        assert_eq!(
            validate_tombstone(current_block_index, tombstone_block_index),
            Ok(())
        );
    }

    {
        // Tombstone is too far in the future.
        let current_block_index = 7;
        let tombstone_block_index = current_block_index + MAX_TOMBSTONE_BLOCKS + 1;
        assert_eq!(
            validate_tombstone(current_block_index, tombstone_block_index),
            Err(TransactionValidationError::TombstoneBlockTooFar)
        );
    }
}

// sense
#[test]
fn test_global_validate_for_blocks_with_sorted_outputs() {
    let mut rng = get_seeded_rng();
    let fee = Mob::MINIMUM_FEE + 1;

    let recipients = vec![
        AccountKey::random(&mut rng).default_subaddress(),
        AccountKey::random(&mut rng).default_subaddress(),
        AccountKey::random(&mut rng).default_subaddress(),
        AccountKey::random(&mut rng).default_subaddress(),
        AccountKey::random(&mut rng).default_subaddress(),
    ];
    let recipients_refs = recipients.iter().collect::<Vec<_>>();

    for block_version in BlockVersion::iterator() {
        // for block version < 3 it doesn't matter
        // for >= 3 it shall return an error about unsorted outputs
        let (tx, ledger) =
            create_test_tx_with_amount_and_comparer_and_recipients::<InverseTxOutputsOrdering>(
                block_version,
                INITIALIZE_LEDGER_AMOUNT - fee,
                fee,
                &recipients_refs,
            );

        let highest_indices = tx.get_membership_proof_highest_indices();
        let root_proofs: Vec<TxOutMembershipProof> = ledger
            .get_tx_out_proof_of_memberships(&highest_indices)
            .expect("failed getting proofs");

        let result = validate(
            &tx,
            tx.prefix.tombstone_block - 1,
            block_version,
            &root_proofs,
            0,
            &mut rng,
        );

        assert_eq!(
            result,
            match block_version.validate_transaction_outputs_are_sorted() {
                true => Err(TransactionValidationError::UnsortedOutputs),
                false => Ok(()),
            }
        )
    }
}

// Test that input rules validation is working
#[test]
fn test_input_rules_validation() {
    let block_version = BlockVersion::THREE;

    let (mut tx, _ledger) = create_test_tx(block_version);

    // Check that the Tx is following input rules (vacuously)
    validate_all_input_rules(block_version, &tx).unwrap();

    // Modify the Tx to have some input rules.
    // (This invalidates the signature, but we aren't checking that here)
    let first_tx_out = tx.prefix.outputs[0].clone();

    // Declare the first tx out as a required output
    tx.prefix.inputs[0].input_rules = Some(InputRules {
        required_outputs: vec![first_tx_out],
        max_tombstone_block: 0,
    });

    // Check that the Tx is following input rules (the required output is there)
    validate_all_input_rules(block_version, &tx).unwrap();

    // Modify the input rules to refer to a non-existent tx out
    let rules = tx.prefix.inputs[0].input_rules.as_mut().unwrap();
    rules.required_outputs[0].masked_amount.masked_value += 1;

    assert!(validate_all_input_rules(block_version, &tx).is_err());

    // Set masked value back, now modify tombstone block
    let rules = tx.prefix.inputs[0].input_rules.as_mut().unwrap();
    rules.required_outputs[0].masked_amount.masked_value -= 1;
    rules.max_tombstone_block = tx.prefix.tombstone_block - 1;

    assert!(validate_all_input_rules(block_version, &tx).is_err());

    // Set the tombstone block limit to be more permissive, now everything should be
    // good
    let rules = tx.prefix.inputs[0].input_rules.as_mut().unwrap();
    rules.max_tombstone_block = tx.prefix.tombstone_block;

    validate_all_input_rules(block_version, &tx).unwrap();
}
