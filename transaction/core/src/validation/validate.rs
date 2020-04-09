// Copyright (c) 2018-2020 MobileCoin Inc.

//! Transaction validation.

extern crate alloc;

use alloc::vec::Vec;

use super::error::{TransactionValidationError, TransactionValidationResult};
use crate::{
    constants::*,
    membership_proofs::{derive_proof_at_index, is_membership_proof_valid},
    range_proofs::check_range_proofs,
    ring_signature::{get_input_rows, verify},
    tx::{Tx, TxOut, TxOutMembershipProof, TxPrefix},
};
use bulletproofs::RangeProof;
use common::HashSet;
use curve25519_dalek::ristretto::CompressedRistretto;
use rand_core::{CryptoRng, RngCore};

/// Determines if the transaction is valid, with respect to the provided context.
///
/// # Arguments
/// * `tx` - A pending transaction.
/// * `current_block_index` - The index of the current block that is being built.
/// * `root_proofs` - Membership proofs for each input ring element contained in `tx`.
/// * `
pub fn validate<R: RngCore + CryptoRng>(
    tx: &Tx,
    current_block_index: u64,
    root_proofs: &[TxOutMembershipProof],
    csprng: &mut R,
) -> TransactionValidationResult<()> {
    validate_number_of_inputs(&tx.prefix, MAX_INPUTS)?;

    validate_number_of_outputs(&tx.prefix, MAX_OUTPUTS)?;

    validate_ring_sizes(&tx.prefix, MIN_RING_SIZE, MAX_RING_SIZE)?;

    validate_ring_elements_are_unique(&tx.prefix)?;

    validate_membership_proofs(&tx.prefix, &root_proofs)?;

    validate_range_proofs(&tx, csprng)?;

    validate_transaction_signature(&tx)?;

    validate_transaction_fee(&tx)?;

    validate_key_images_are_unique(&tx)?;

    validate_tombstone(current_block_index, tx.tombstone_block)?;

    // TODO: The transaction must not contain a Key Image that has previously been spent.
    // This should be implemented using proofs-of-non-membership, but could be implemented
    // by a check in untrusted code.

    Ok(())
}

/// The transaction must have at least one input, and no more than the maximum allowed number of inputs.
fn validate_number_of_inputs(
    tx_prefix: &TxPrefix,
    maximum_allowed_inputs: u16,
) -> TransactionValidationResult<()> {
    let num_inputs = tx_prefix.inputs.len();

    // Each transaction must have at least one input.
    if num_inputs == 0 {
        return Err(TransactionValidationError::NoInputs);
    }

    // Each transaction must have no more than the maximum allowed number of inputs.
    if num_inputs > maximum_allowed_inputs as usize {
        return Err(TransactionValidationError::TooManyInputs);
    }

    Ok(())
}

/// The transaction must have at least one output.
fn validate_number_of_outputs(
    tx_prefix: &TxPrefix,
    maximum_allowed_outputs: u16,
) -> TransactionValidationResult<()> {
    let num_outputs = tx_prefix.outputs.len();

    // Each transaction must have at least one output.
    if num_outputs == 0 {
        return Err(TransactionValidationError::NoOutputs);
    }

    // Each transaction must have no more than the maximum allowed number of outputs.
    if num_outputs > maximum_allowed_outputs as usize {
        return Err(TransactionValidationError::TooManyOutputs);
    }

    Ok(())
}

/// The transaction's input(s) must each have a ring with an allowable number of elements:
/// * All rings in a transaction must contain the same number of elements.
/// * Each input must contain a ring with no fewer than the minimum number of elements.
/// * Each input must contain a ring with no more than the maximum number of elements.
fn validate_ring_sizes(
    tx_prefix: &TxPrefix,
    minimum_ring_size: usize,
    maximum_ring_size: usize,
) -> TransactionValidationResult<()> {
    let ring_sizes: Vec<usize> = tx_prefix
        .inputs
        .iter()
        .map(|tx_in| tx_in.ring.len())
        .collect();

    // This should be enforced before this function is called by checking the number of inputs.
    assert!(!ring_sizes.is_empty());

    let first_ring_size = ring_sizes[0];
    for ring_size in &ring_sizes {
        // All rings in a transaction must contain the same number of elements.
        if *ring_size != first_ring_size {
            return Err(TransactionValidationError::UnequalRingSizes);
        }

        // Each input must contain a ring with no fewer than the minimum number of elements.
        if *ring_size < minimum_ring_size as usize {
            return Err(TransactionValidationError::InsufficientRingSize);
        }

        // Each input must contain a ring with no more than the maximum number of elements.
        if *ring_size > maximum_ring_size as usize {
            return Err(TransactionValidationError::ExcessiveRingSize);
        }
    }

    Ok(())
}

/// Elements in all rings within the transaction must be unique.
fn validate_ring_elements_are_unique(tx_prefix: &TxPrefix) -> TransactionValidationResult<()> {
    let ring_elements: Vec<&TxOut> = tx_prefix
        .inputs
        .iter()
        .flat_map(|tx_in| tx_in.ring.iter())
        .collect();

    let mut uniques = HashSet::default();
    for tx_out in &ring_elements {
        if !uniques.insert(tx_out) {
            return Err(TransactionValidationError::DuplicateRingElements);
        }
    }

    Ok(())
}

/// All key images within the transaction must be unique.
fn validate_key_images_are_unique(tx: &Tx) -> TransactionValidationResult<()> {
    let mut uniques = HashSet::default();
    for key_image in tx.key_images() {
        if !uniques.insert(key_image) {
            return Err(TransactionValidationError::DuplicateKeyImages);
        }
    }
    Ok(())
}

fn validate_range_proofs<R: RngCore + CryptoRng>(
    tx: &Tx,
    rng: &mut R,
) -> TransactionValidationResult<()> {
    let commitments: Vec<CompressedRistretto> = tx
        .prefix
        .output_commitments()
        .iter()
        .map(|commitment| CompressedRistretto::from_slice(&commitment.to_bytes()))
        .collect();

    let range_proof = RangeProof::from_bytes(&tx.range_proofs)
        .map_err(|_e| TransactionValidationError::InvalidRangeProof)?;

    check_range_proofs(&range_proof, &commitments, rng)
        .map_err(|_e| TransactionValidationError::InvalidRangeProof)
}

fn validate_transaction_signature(tx: &Tx) -> TransactionValidationResult<()> {
    let prefix_hash = tx.prefix.hash();
    let input_rows = get_input_rows(&tx.prefix.inputs)?;
    let commitments = tx.prefix.output_commitments();

    if !verify(&prefix_hash.0, &input_rows, &commitments, &tx.signature) {
        return Err(TransactionValidationError::InvalidTransactionSignature);
    }

    Ok(())
}

/// The fee amount must be greater than or equal to `BASE_FEE`.
fn validate_transaction_fee(tx: &Tx) -> TransactionValidationResult<()> {
    if tx.prefix.fee < BASE_FEE {
        Err(TransactionValidationError::TxFeeError)
    } else {
        Ok(())
    }
}

/// Validate TxOut membership proofs.
///
/// # Arguments
/// * `tx_prefix` - Prefix of the transaction being validated.
/// * `root_proofs` - Proofs of membership, provided by the untrusted system, that are used to check
///         the root hashes of the transaction's membership proofs.
fn validate_membership_proofs(
    tx_prefix: &TxPrefix,
    root_proofs: &[TxOutMembershipProof],
) -> TransactionValidationResult<()> {
    // Each ring element must have a corresponding membership proof.
    for tx_in in &tx_prefix.inputs {
        if tx_in.ring.len() != tx_in.proofs.len() {
            return Err(TransactionValidationError::MissingTxOutMembershipProof);
        }
    }

    let tx_out_with_membership_proof: Vec<(&TxOut, &TxOutMembershipProof)> = tx_prefix
        .inputs
        .iter()
        .flat_map(|tx_in| {
            let zipped: Vec<(&TxOut, &TxOutMembershipProof)> =
                tx_in.ring.iter().zip(&tx_in.proofs).collect();
            zipped
        })
        .collect();

    // Each TxOut used as input must have a corresponding "root proof".
    // This could later be optimized if multiple input TxOuts have membership proofs that
    // share the same root hash.
    if tx_out_with_membership_proof.len() != root_proofs.len() {
        return Err(TransactionValidationError::InvalidLedgerContext);
    }

    struct TxOutWithProofs<'a> {
        /// A TxOut used as an input ring element.
        tx_out: &'a TxOut,

        /// A membership proof for `tx_out` provided by the transaction author.
        membership_proof: &'a TxOutMembershipProof,

        /// A "root" membership proof, provided by the untrusted ledger server.
        root_proof: &'a TxOutMembershipProof,
    }

    let mut tx_outs_with_proofs: Vec<TxOutWithProofs> = Vec::new();
    for (i, (tx_out, membership_proof)) in tx_out_with_membership_proof.iter().enumerate() {
        let root_proof: &TxOutMembershipProof = &root_proofs[i];
        let tx_out_with_proofs = TxOutWithProofs {
            tx_out,
            membership_proof,
            root_proof,
        };
        tx_outs_with_proofs.push(tx_out_with_proofs);
    }

    // Validate the membership proof for each TxOut used as an input ring element.
    for tx_out_with_proofs in tx_outs_with_proofs {
        match derive_proof_at_index(&tx_out_with_proofs.root_proof) {
            Err(_e) => {
                return Err(TransactionValidationError::InvalidLedgerContext);
            }
            Ok(derived_proof) => {
                match derived_proof.elements.last() {
                    None => {
                        return Err(TransactionValidationError::InvalidLedgerContext);
                    }
                    Some(element) => {
                        // Check the tx_out's membership proof against this root hash.
                        match is_membership_proof_valid(
                            tx_out_with_proofs.tx_out,
                            tx_out_with_proofs.membership_proof,
                            element.hash.as_ref(),
                        ) {
                            Err(_e) => {
                                return Err(
                                    TransactionValidationError::MembershipProofValidationError,
                                );
                            }
                            Ok(is_valid) => {
                                if !is_valid {
                                    return Err(
                                        TransactionValidationError::InvalidTxOutMembershipProof,
                                    );
                                }
                                // Else, the membership proof is valid.
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// The transaction must be not have expired, or be too long-lived.
///
/// # Arguments
/// * `current_block_index` - The index of the block currently being built.
/// * `tombstone_block_index` - The block index at which this transaction is no longer considered valid.
///
pub fn validate_tombstone(
    current_block_index: u64,
    tombstone_block_index: u64,
) -> TransactionValidationResult<()> {
    if current_block_index >= tombstone_block_index {
        return Err(TransactionValidationError::TombstoneBlockExceeded);
    }

    let limit = current_block_index + MAX_TOMBSTONE_BLOCKS;
    if tombstone_block_index > limit {
        return Err(TransactionValidationError::TombstoneBlockTooFar);
    }

    Ok(())
}

#[cfg(test)]
#[allow(unused)]
mod tests {
    extern crate alloc;
    use alloc::{string::ToString, vec::Vec};

    use crate::{
        account_keys::{AccountKey, PublicAddress},
        constants::{BASE_FEE, MIN_RING_SIZE},
        get_tx_out_shared_secret,
        onetime_keys::recover_onetime_private_key,
        ring_signature::{Commitment, KeyImage},
        tx::{Tx, TxOut, TxOutMembershipHash, TxOutMembershipProof, TxPrefix},
        validation::{
            error::TransactionValidationError,
            validate::{
                validate_key_images_are_unique, validate_membership_proofs,
                validate_number_of_inputs, validate_number_of_outputs, validate_range_proofs,
                validate_ring_elements_are_unique, validate_ring_sizes, validate_tombstone,
                validate_transaction_fee, validate_transaction_signature, MAX_TOMBSTONE_BLOCKS,
            },
        },
    };
    use keys::{CompressedRistrettoPublic, RistrettoPublic};
    use ledger_db::{Ledger, LedgerDB};
    use mcserial::ReprBytes32;
    use rand::{rngs::StdRng, SeedableRng};
    use serde::{de::DeserializeOwned, ser::Serialize};
    use tempdir::TempDir;
    use transaction_test_utils::{
        create_ledger, create_transaction, create_transaction_with_amount, initialize_ledger,
        INITIALIZE_LEDGER_AMOUNT,
    };

    // HACK: To test validation we need valid Tx objects. The code to create them is complicated,
    // and a variant of it resides inside the `transaction_test_utils` crate. However,when we
    // depend on it in our [dev-dependencies], it will compile and link against another copy of
    // this crate, since cargo is weird like that.
    // Relying in the fact that both data structures are actually the same, this hack lets us
    // convert from the `transaction` crate being compiled by `transaction_test_utils` to the one
    // compiled as part of building test tests.
    // If we want to avoid this hack, we could move transaction validation into its own crate.
    fn adapt_hack<Src: Serialize, Dst: DeserializeOwned>(src: &Src) -> Dst {
        let bytes = mcserial::serialize(src).unwrap();
        mcserial::deserialize(&bytes).unwrap()
    }

    fn create_test_tx() -> (Tx, LedgerDB) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let sender = transaction_test_utils::AccountKey::random(&mut rng);
        let mut ledger = create_ledger();
        let n_blocks = 1;
        initialize_ledger(&mut ledger, n_blocks, &sender, &mut rng);

        let mut transactions = ledger.get_transactions_by_block(n_blocks - 1).unwrap();
        let tx_stored = transactions.pop().unwrap();
        let tx_out = tx_stored.outputs[0].clone();

        let recipient = transaction_test_utils::AccountKey::random(&mut rng);
        let tx = create_transaction(
            &mut ledger,
            &tx_out,
            &sender,
            &recipient.default_subaddress(),
            n_blocks + 1,
            &mut rng,
        );

        // Hack: TODO explain this
        (adapt_hack(&tx), ledger)
    }

    fn create_test_tx_with_amount(amount: u64, fee: u64) -> (Tx, LedgerDB) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let sender = transaction_test_utils::AccountKey::random(&mut rng);
        let mut ledger = create_ledger();
        let n_blocks = 1;
        initialize_ledger(&mut ledger, n_blocks, &sender, &mut rng);

        let mut transactions = ledger.get_transactions_by_block(n_blocks - 1).unwrap();
        let tx_stored = transactions.pop().unwrap();
        let tx_out = tx_stored.outputs[0].clone();

        let recipient = transaction_test_utils::AccountKey::random(&mut rng);
        let tx = create_transaction_with_amount(
            &mut ledger,
            &tx_out,
            &sender,
            &recipient.default_subaddress(),
            amount,
            fee,
            n_blocks + 1,
            &mut rng,
        );

        // Hack: TODO explain this
        (adapt_hack(&tx), ledger)
    }

    #[test]
    // Should return Ok(()) when the Tx's membership proofs are correct and agree with ledger.
    fn test_validate_membership_proofs() {
        let (tx, ledger) = create_test_tx();

        let highest_indices = tx.get_membership_proof_highest_indices();
        let root_proofs: Vec<TxOutMembershipProof> = adapt_hack(
            &ledger
                .get_tx_out_proof_of_memberships(&highest_indices)
                .expect("failed getting proofs"),
        );

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
            let root_proofs: Vec<TxOutMembershipProof> = adapt_hack(
                &ledger
                    .get_tx_out_proof_of_memberships(&highest_indices)
                    .expect("failed getting proofs"),
            );
            assert_eq!(validate_membership_proofs(&tx.prefix, &root_proofs), Ok(()));
        }
    }

    #[test]
    fn test_validate_number_of_inputs() {
        let (orig_tx, _ledger) = create_test_tx();
        let max_inputs = 25;

        for num_inputs in 0..100 {
            let mut tx_prefix = orig_tx.prefix.clone();
            tx_prefix.inputs.clear();
            for i in 0..num_inputs {
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

    #[test]
    fn test_validate_number_of_outputs() {
        let (orig_tx, _ledger) = create_test_tx();
        let max_outputs = 25;

        for num_outputs in 0..100 {
            let mut tx_prefix = orig_tx.prefix.clone();
            tx_prefix.outputs.clear();
            for i in 0..num_outputs {
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

    #[test]
    fn test_validate_ring_sizes() {
        let (orig_tx, _ledger) = create_test_tx();
        assert_eq!(orig_tx.prefix.inputs.len(), 1);
        let min_ring_size = MIN_RING_SIZE;
        let max_ring_size = min_ring_size + 3;

        // A transaction with a single input and ring size of 0.
        {
            let mut tx_prefix = orig_tx.prefix.clone();
            tx_prefix.inputs[0].ring.clear();

            assert_eq!(
                validate_ring_sizes(&tx_prefix, min_ring_size, max_ring_size),
                Err(TransactionValidationError::InsufficientRingSize),
            );
        }

        // A transaction with a single input and ring size < minimum_ring_size.
        {
            let mut tx_prefix = orig_tx.prefix.clone();
            tx_prefix.inputs[0].ring.truncate(min_ring_size - 1);

            assert_eq!(
                validate_ring_sizes(&tx_prefix, min_ring_size, max_ring_size),
                Err(TransactionValidationError::InsufficientRingSize),
            );
        }

        // A transaction with a single input and ring size = minimum_ring_size.
        {
            assert_eq!(orig_tx.prefix.inputs[0].ring.len(), min_ring_size);

            assert_eq!(
                validate_ring_sizes(&orig_tx.prefix, min_ring_size, max_ring_size),
                Ok(())
            );
        }

        // A transaction with a single input and minimum_ring_size < ring size < maximum_ring_size.
        {
            let mut tx_prefix = orig_tx.prefix.clone();
            tx_prefix.inputs[0]
                .ring
                .push(orig_tx.prefix.inputs[0].ring[0].clone());

            assert_eq!(
                validate_ring_sizes(&tx_prefix, min_ring_size, max_ring_size),
                Ok(())
            );
        }

        // A transaction with a single input ring size = maximum_ring_size.
        {
            let mut tx_prefix = orig_tx.prefix.clone();
            for _ in 0..max_ring_size - min_ring_size {
                tx_prefix.inputs[0]
                    .ring
                    .push(orig_tx.prefix.inputs[0].ring[0].clone());
            }
            assert_eq!(tx_prefix.inputs[0].ring.len(), max_ring_size);

            assert_eq!(
                validate_ring_sizes(&tx_prefix, min_ring_size, max_ring_size),
                Ok(())
            );
        }

        // A transaction with a single input ring size > maximum_ring_size.
        {
            let mut tx_prefix = orig_tx.prefix.clone();
            for _ in 0..=max_ring_size - min_ring_size {
                tx_prefix.inputs[0]
                    .ring
                    .push(orig_tx.prefix.inputs[0].ring[0].clone());
            }
            assert_eq!(tx_prefix.inputs[0].ring.len(), max_ring_size + 1);

            assert_eq!(
                validate_ring_sizes(&tx_prefix, min_ring_size, max_ring_size),
                Err(TransactionValidationError::ExcessiveRingSize)
            );
        }

        // A transaction with multiple inputs and unequal ring sizes.
        {
            let mut tx_prefix = orig_tx.prefix.clone();
            tx_prefix.inputs.push(orig_tx.prefix.inputs[0].clone());
            tx_prefix.inputs[1]
                .ring
                .push(orig_tx.prefix.inputs[0].ring[0].clone());

            assert_eq!(
                validate_ring_sizes(&tx_prefix, min_ring_size, max_ring_size),
                Err(TransactionValidationError::UnequalRingSizes)
            );
        }
    }

    #[test]
    fn test_validate_ring_elements_are_unique() {
        let (orig_tx, _ledger) = create_test_tx();
        assert_eq!(orig_tx.prefix.inputs.len(), 1);
        let min_ring_size = MIN_RING_SIZE;
        let max_ring_size = min_ring_size + 3;

        // A transaction with a single input and unique ring elements.
        {
            let mut tx_prefix = orig_tx.prefix.clone();
            assert_eq!(tx_prefix.inputs.len(), 1);

            assert_eq!(validate_ring_elements_are_unique(&tx_prefix), Ok(()));
        }

        // A transaction with a single input and duplicate ring elements.
        {
            let mut tx_prefix = orig_tx.prefix.clone();
            assert_eq!(tx_prefix.inputs.len(), 1);

            tx_prefix.inputs[0]
                .ring
                .push(orig_tx.prefix.inputs[0].ring[0].clone());

            assert_eq!(
                validate_ring_elements_are_unique(&tx_prefix),
                Err(TransactionValidationError::DuplicateRingElements)
            );
        }

        // A transaction with a multiple inputs and unique ring elements.
        {
            let mut tx_prefix = orig_tx.prefix.clone();
            tx_prefix.inputs.push(orig_tx.prefix.inputs[0].clone());

            for mut tx_out in tx_prefix.inputs[1].ring.iter_mut() {
                let mut bytes = tx_out.target_key.to_bytes();
                bytes[0] = !bytes[0];
                tx_out.target_key = CompressedRistrettoPublic::from_bytes(&bytes).unwrap();
            }

            assert_eq!(validate_ring_elements_are_unique(&tx_prefix), Ok(()));
        }

        // A transaction with a multiple inputs and duplicate ring elements in different rings.
        {
            let mut tx_prefix = orig_tx.prefix.clone();
            tx_prefix.inputs.push(orig_tx.prefix.inputs[0].clone());

            assert_eq!(
                validate_ring_elements_are_unique(&tx_prefix),
                Err(TransactionValidationError::DuplicateRingElements)
            );
        }
    }

    #[test]
    #[ignore]
    fn test_validate_ring_elements_are_sorted() {
        unimplemented!()
    }

    #[test]
    /// validate_key_images_are_unique rejects duplicate key image.
    fn test_validate_key_images_are_unique_rejects_duplicate() {
        let (mut tx, _ledger) = create_test_tx();
        let key_image = tx.key_images()[0].clone();
        tx.signature.key_images.push(key_image);

        assert_eq!(
            validate_key_images_are_unique(&tx),
            Err(TransactionValidationError::DuplicateKeyImages)
        );
    }

    #[test]
    /// validate_key_images_are_unique rejects returns Ok if all key images are unique.
    fn test_validate_key_images_are_unique_ok() {
        let (tx, _ledger) = create_test_tx();
        assert_eq!(validate_key_images_are_unique(&tx), Ok(()),);
    }

    #[test]
    fn test_validate_range_proofs() {
        let (orig_tx, _ledger) = create_test_tx();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        // Valid range proofs
        {
            assert_eq!(validate_range_proofs(&orig_tx, &mut rng), Ok(()));
        }

        // Range proofs that contain invalid data
        {
            let mut tx = orig_tx.clone();
            tx.range_proofs = vec![1, 2, 3];
            assert_eq!(
                validate_range_proofs(&tx, &mut rng),
                Err(TransactionValidationError::InvalidRangeProof)
            );
        }

        // Invalid range proof
        {
            let mut tx = orig_tx.clone();
            tx.prefix.outputs[0].amount.commitment = Commitment::from(46);
            assert_eq!(
                validate_range_proofs(&tx, &mut rng),
                Err(TransactionValidationError::InvalidRangeProof)
            );
        }
    }

    #[test]
    fn test_validate_transaction_signature() {
        let (orig_tx, _ledger) = create_test_tx();

        // Valid signature
        {
            assert_eq!(validate_transaction_signature(&orig_tx), Ok(()));
        }

        // Invalid signature due to altered input
        {
            let mut tx = orig_tx.clone();
            tx.prefix.inputs[0].ring.pop();

            assert_eq!(
                validate_transaction_signature(&tx),
                Err(TransactionValidationError::InvalidTransactionSignature)
            );
        }

        // Invalid signature due to altered output
        {
            let mut tx = orig_tx.clone();
            tx.prefix.outputs[0].amount.commitment = Commitment::from(46);

            assert_eq!(
                validate_transaction_signature(&tx),
                Err(TransactionValidationError::InvalidTransactionSignature)
            );
        }

        // Sanity - a transaction with sum(inputs) = sum(outputs) validates.
        {
            // The amount here needs to be bigger than whatever is used in `initialize_ledger`.
            let (tx, _ledger) =
                create_test_tx_with_amount(INITIALIZE_LEDGER_AMOUNT - BASE_FEE, BASE_FEE);
            assert_eq!(validate_transaction_signature(&tx), Ok(()));
        }
    }

    #[test]
    fn test_validate_transaction_fee() {
        {
            // Zero fees gets rejected
            let (tx, _ledger) = create_test_tx_with_amount(INITIALIZE_LEDGER_AMOUNT, 0);
            assert_eq!(
                validate_transaction_fee(&tx),
                Err(TransactionValidationError::TxFeeError)
            );
        }

        {
            // Off by one fee gets rejected
            let fee = BASE_FEE - 1;
            let (tx, _ledger) = create_test_tx_with_amount(INITIALIZE_LEDGER_AMOUNT - fee, fee);
            assert_eq!(
                validate_transaction_fee(&tx),
                Err(TransactionValidationError::TxFeeError)
            );
        }

        {
            // Exact fee amount is okay
            let (tx, _ledger) =
                create_test_tx_with_amount(INITIALIZE_LEDGER_AMOUNT - BASE_FEE, BASE_FEE);
            assert_eq!(validate_transaction_fee(&tx), Ok(()));
        }

        {
            // Overpaying fees is okay
            let fee = BASE_FEE + 1;
            let (tx, _ledger) = create_test_tx_with_amount(INITIALIZE_LEDGER_AMOUNT - fee, fee);
            assert_eq!(validate_transaction_fee(&tx), Ok(()));
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
    /// Should return TombstoneBlockTooFar if the tombstone is too far in the future.
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
}
