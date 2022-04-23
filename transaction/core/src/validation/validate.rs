// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Transaction validation.

extern crate alloc;

use alloc::{format, vec::Vec};

use super::error::{TransactionValidationError, TransactionValidationResult};
use crate::{
    constants::*,
    membership_proofs::{derive_proof_at_index, is_membership_proof_valid},
    tx::{Tx, TxOut, TxOutMembershipProof, TxPrefix},
    Amount, BlockVersion, CompressedCommitment, TokenId,
};
use mc_common::HashSet;
use mc_crypto_keys::CompressedRistrettoPublic;
use rand_core::{CryptoRng, RngCore};

/// Determines if the transaction is valid, with respect to the provided
/// context.
///
/// # Arguments
/// * `tx` - A pending transaction.
/// * `current_block_index` - The index of the current block that is being
///   built.
/// * `block_version` - The version of the transaction rules we are testing
/// * `root_proofs` - Membership proofs for each input ring element contained in
///   `tx`.
/// * `minimum_fee` - The minimum fee for the token indicated by
///   tx.prefix.fee_token_id
/// * `csprng` - Cryptographically secure random number generator.
pub fn validate<R: RngCore + CryptoRng>(
    tx: &Tx,
    current_block_index: u64,
    block_version: BlockVersion,
    root_proofs: &[TxOutMembershipProof],
    minimum_fee: u64,
    csprng: &mut R,
) -> TransactionValidationResult<()> {
    if BlockVersion::MAX < block_version {
        return Err(TransactionValidationError::Ledger(format!(
            "Invalid block version: {}",
            block_version
        )));
    }

    validate_number_of_inputs(&tx.prefix, MAX_INPUTS)?;

    validate_number_of_outputs(&tx.prefix, MAX_OUTPUTS)?;

    validate_ring_sizes(&tx.prefix, RING_SIZE)?;

    validate_ring_elements_are_unique(&tx.prefix)?;

    validate_ring_elements_are_sorted(&tx.prefix)?;

    validate_inputs_are_sorted(&tx.prefix)?;

    validate_membership_proofs(&tx.prefix, root_proofs)?;

    validate_signature(block_version, tx, csprng)?;

    validate_transaction_fee(tx, minimum_fee)?;

    validate_key_images_are_unique(tx)?;

    validate_outputs_public_keys_are_unique(tx)?;

    validate_tombstone(current_block_index, tx.prefix.tombstone_block)?;

    // Note: The transaction must not contain a Key Image that has previously been
    // spent. This must be checked outside the enclave.

    // Each tx_out must conform to the structural rules for TxOut's at this block
    // version
    for tx_out in tx.prefix.outputs.iter() {
        validate_tx_out(block_version, tx_out)?;
    }

    ////
    // Validate rules which depend on block version (see MCIP #26)
    ////

    if block_version.validate_transaction_outputs_are_sorted() {
        validate_outputs_are_sorted(&tx.prefix)?;
    }

    Ok(())
}

/// Determines if a tx out conforms to the current block version rules
pub fn validate_tx_out(
    block_version: BlockVersion,
    tx_out: &TxOut,
) -> TransactionValidationResult<()> {
    // If memos are supported, then all outputs must have memo fields.
    // If memos are not yet supported, then no outputs may have memo fields.
    if block_version.e_memo_feature_is_supported() {
        validate_memo_exists(tx_out)?;
    } else {
        validate_no_memo_exists(tx_out)?;
    }

    // If masked token id is supported, then all outputs must have masked_token_id
    // If masked token id is not yet supported, then no outputs may have
    // masked_token_id
    //
    // Note: This rct_bulletproofs code enforces that token_id = 0 if this feature
    // is not enabled
    if block_version.masked_token_id_feature_is_supported() {
        validate_masked_token_id_exists(tx_out)?;
    } else {
        validate_no_masked_token_id_exists(tx_out)?;
    }

    Ok(())
}

/// The transaction must have at least one input, and no more than the maximum
/// allowed number of inputs.
fn validate_number_of_inputs(
    tx_prefix: &TxPrefix,
    maximum_allowed_inputs: u64,
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
    maximum_allowed_outputs: u64,
) -> TransactionValidationResult<()> {
    let num_outputs = tx_prefix.outputs.len();

    // Each transaction must have at least one output.
    if num_outputs == 0 {
        return Err(TransactionValidationError::NoOutputs);
    }

    // Each transaction must have no more than the maximum allowed number of
    // outputs.
    if num_outputs > maximum_allowed_outputs as usize {
        return Err(TransactionValidationError::TooManyOutputs);
    }

    Ok(())
}

/// Each input must contain a ring containing `ring_size` elements.
fn validate_ring_sizes(tx_prefix: &TxPrefix, ring_size: usize) -> TransactionValidationResult<()> {
    for input in &tx_prefix.inputs {
        if input.ring.len() != ring_size {
            let e = if input.ring.len() > ring_size {
                TransactionValidationError::ExcessiveRingSize
            } else {
                TransactionValidationError::InsufficientRingSize
            };
            return Err(e);
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

    check_unique(
        &ring_elements,
        TransactionValidationError::DuplicateRingElements,
    )
}

/// Elements in a ring must be sorted.
fn validate_ring_elements_are_sorted(tx_prefix: &TxPrefix) -> TransactionValidationResult<()> {
    for tx_in in &tx_prefix.inputs {
        check_sorted(
            &tx_in.ring,
            |a, b| a.public_key < b.public_key,
            TransactionValidationError::UnsortedRingElements,
        )?;
    }

    Ok(())
}

/// Inputs must be sorted by the public key of the first ring element of each
/// input.
fn validate_inputs_are_sorted(tx_prefix: &TxPrefix) -> TransactionValidationResult<()> {
    check_sorted(
        &tx_prefix.inputs,
        |a, b| {
            !a.ring.is_empty() && !b.ring.is_empty() && a.ring[0].public_key < b.ring[0].public_key
        },
        TransactionValidationError::UnsortedInputs,
    )
}

fn validate_outputs_are_sorted(tx_prefix: &TxPrefix) -> TransactionValidationResult<()> {
    check_sorted(
        &tx_prefix.outputs,
        |a, b| a.public_key < b.public_key,
        TransactionValidationError::UnsortedOutputs,
    )
}

/// All key images within the transaction must be unique.
fn validate_key_images_are_unique(tx: &Tx) -> TransactionValidationResult<()> {
    check_unique(
        &tx.key_images(),
        TransactionValidationError::DuplicateKeyImages,
    )
}

/// All output public keys within the transaction must be unique.
fn validate_outputs_public_keys_are_unique(tx: &Tx) -> TransactionValidationResult<()> {
    check_unique(
        &tx.output_public_keys(),
        TransactionValidationError::DuplicateOutputPublicKey,
    )
}

/// All outputs have no memo (new-style TxOuts (Post MCIP #3) are rejected)
fn validate_no_memo_exists(tx_out: &TxOut) -> TransactionValidationResult<()> {
    if tx_out.e_memo.is_some() {
        return Err(TransactionValidationError::MemosNotAllowed);
    }
    Ok(())
}

/// All outputs have a memo (old-style TxOuts (Pre MCIP #3) are rejected)
fn validate_memo_exists(tx_out: &TxOut) -> TransactionValidationResult<()> {
    if tx_out.e_memo.is_none() {
        return Err(TransactionValidationError::MissingMemo);
    }
    Ok(())
}

/// All outputs have no masked token id (new-style TxOuts (Post MCIP #25) are
/// rejected)
fn validate_no_masked_token_id_exists(tx_out: &TxOut) -> TransactionValidationResult<()> {
    if !tx_out.masked_amount.masked_token_id.is_empty() {
        return Err(TransactionValidationError::MaskedTokenIdNotAllowed);
    }
    Ok(())
}

/// All outputs have a masked token id (old-style TxOuts (Pre MCIP #25) are
/// rejected)
fn validate_masked_token_id_exists(tx_out: &TxOut) -> TransactionValidationResult<()> {
    if tx_out.masked_amount.masked_token_id.len() != TokenId::NUM_BYTES {
        return Err(TransactionValidationError::MissingMaskedTokenId);
    }
    Ok(())
}

/// Verifies the transaction signature.
///
/// A valid RctBulletproofs signature implies that:
/// * tx.prefix has not been modified,
/// * The signer owns one element in each input ring,
/// * Each key image corresponds to the spent ring element,
/// * The outputs have values in [0,2^64),
/// * The transaction does not create or destroy mobilecoins.
/// * The signature is valid according to the rules of this block version
pub fn validate_signature<R: RngCore + CryptoRng>(
    block_version: BlockVersion,
    tx: &Tx,
    rng: &mut R,
) -> TransactionValidationResult<()> {
    let rings: Vec<Vec<(CompressedRistrettoPublic, CompressedCommitment)>> = tx
        .prefix
        .inputs
        .iter()
        .map(|input| {
            input
                .ring
                .iter()
                .map(|tx_out| (tx_out.target_key, tx_out.masked_amount.commitment))
                .collect()
        })
        .collect();

    let output_commitments = tx.prefix.output_commitments();

    let tx_prefix_hash = tx.prefix.hash();
    let message = tx_prefix_hash.as_bytes();

    tx.signature
        .verify(
            block_version,
            message,
            &rings,
            &output_commitments,
            Amount::new(tx.prefix.fee, TokenId::from(tx.prefix.fee_token_id)),
            rng,
        )
        .map_err(TransactionValidationError::InvalidTransactionSignature)
}

/// The fee amount must be greater than or equal to the given minimum fee.
fn validate_transaction_fee(tx: &Tx, minimum_fee: u64) -> TransactionValidationResult<()> {
    if tx.prefix.fee < minimum_fee {
        Err(TransactionValidationError::TxFeeError)
    } else {
        Ok(())
    }
}

/// Validate TxOut membership proofs.
///
/// # Arguments
/// * `tx_prefix` - Prefix of the transaction being validated.
/// * `root_proofs` - Proofs of membership, provided by the untrusted system,
///   that are used to check the root hashes of the transaction's membership
///   proofs.
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
    // This could later be optimized if multiple input TxOuts have membership proofs
    // that share the same root hash.
    if tx_out_with_membership_proof.len() != root_proofs.len() {
        return Err(TransactionValidationError::InvalidLedgerContext);
    }

    // Each root proof must contain valid ranges.
    // (Ranges in the transaction's membership proofs are checked in
    // `is_membership_proof_valid`).
    for root_proof in root_proofs {
        if root_proof
            .elements
            .iter()
            .any(|element| element.range.from > element.range.to)
        {
            return Err(TransactionValidationError::MembershipProofValidationError);
        }
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
        match derive_proof_at_index(tx_out_with_proofs.root_proof) {
            Err(_e) => {
                return Err(TransactionValidationError::InvalidLedgerContext);
            }
            Ok(derived_proof) => {
                match crate::membership_proofs::compute_implied_merkle_root(&derived_proof) {
                    Err(_) => {
                        return Err(TransactionValidationError::InvalidLedgerContext);
                    }
                    Ok(root_element) => {
                        // Check the tx_out's membership proof against this root hash.
                        match is_membership_proof_valid(
                            tx_out_with_proofs.tx_out,
                            tx_out_with_proofs.membership_proof,
                            root_element.hash.as_ref(),
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
/// * `tombstone_block_index` - The block index at which this transaction is no
///   longer considered valid.
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

fn check_sorted<T>(
    values: &[T],
    ordered: fn(&T, &T) -> bool,
    err: TransactionValidationError,
) -> TransactionValidationResult<()> {
    if !values.windows(2).all(|pair| ordered(&pair[0], &pair[1])) {
        return Err(err);
    }

    Ok(())
}

fn check_unique<T: Eq + core::hash::Hash>(
    values: &[T],
    err: TransactionValidationError,
) -> TransactionValidationResult<()> {
    let mut uniques = HashSet::default();
    for x in values {
        if !uniques.insert(x) {
            return Err(err);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate alloc;

    use alloc::vec::Vec;

    use crate::{
        constants::RING_SIZE,
        tokens::Mob,
        tx::{Tx, TxOutMembershipHash, TxOutMembershipProof},
        validation::error::TransactionValidationError,
        Token,
    };

    use crate::membership_proofs::Range;
    use mc_crypto_keys::{CompressedRistrettoPublic, ReprBytes};
    use mc_ledger_db::{Ledger, LedgerDB};
    use mc_transaction_core_test_utils::{
        create_ledger, create_transaction, create_transaction_with_amount_and_comparer,
        initialize_ledger, AccountKey, InverseTxOutputsOrdering, INITIALIZE_LEDGER_AMOUNT,
    };
    use mc_transaction_std::{DefaultTxOutputsOrdering, TxOutputsOrdering};
    use rand::{rngs::StdRng, SeedableRng};
    use serde::{de::DeserializeOwned, ser::Serialize};

    // HACK: To test validation we need valid Tx objects. The code to create them is
    // complicated, and a variant of it resides inside the
    // `transaction_test_utils` crate. However,when we depend on it in our
    // [dev-dependencies], it will compile and link against another copy of this
    // crate, since cargo is weird like that. Relying in the fact that both data
    // structures are actually the same, this hack lets us convert from the
    // `transaction` crate being compiled by `transaction_test_utils` to the one
    // compiled as part of building test tests.
    // If we want to avoid this hack, we could move transaction validation into its
    // own crate.
    fn adapt_hack<Src: Serialize, Dst: DeserializeOwned>(src: &Src) -> Dst {
        let bytes = mc_util_serial::serialize(src).unwrap();
        mc_util_serial::deserialize(&bytes).unwrap()
    }

    fn create_test_tx(block_version: BlockVersion) -> (Tx, LedgerDB) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let mut ledger = create_ledger();
        let n_blocks = 1;
        initialize_ledger(
            adapt_hack(&block_version),
            &mut ledger,
            n_blocks,
            &sender,
            &mut rng,
        );

        // Spend an output from the last block.
        let block_contents = ledger.get_block_contents(n_blocks - 1).unwrap();
        let tx_out = block_contents.outputs[0].clone();

        let recipient = AccountKey::random(&mut rng);
        let tx = create_transaction(
            adapt_hack(&block_version),
            &mut ledger,
            &tx_out,
            &sender,
            &recipient.default_subaddress(),
            n_blocks + 1,
            &mut rng,
        );

        (adapt_hack(&tx), ledger)
    }

    fn create_test_tx_with_amount(
        block_version: BlockVersion,
        amount: u64,
        fee: u64,
    ) -> (Tx, LedgerDB) {
        create_test_tx_with_amount_and_comparer::<DefaultTxOutputsOrdering>(
            block_version,
            amount,
            fee,
        )
    }

    fn create_test_tx_with_amount_and_comparer<O: TxOutputsOrdering>(
        block_version: BlockVersion,
        amount: u64,
        fee: u64,
    ) -> (Tx, LedgerDB) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let mut ledger = create_ledger();
        let n_blocks = 1;
        initialize_ledger(
            adapt_hack(&block_version),
            &mut ledger,
            n_blocks,
            &sender,
            &mut rng,
        );

        // Spend an output from the last block.
        let block_contents = ledger.get_block_contents(n_blocks - 1).unwrap();
        let tx_out = block_contents.outputs[0].clone();

        let recipient = AccountKey::random(&mut rng);
        let tx = create_transaction_with_amount_and_comparer::<_, _, O>(
            adapt_hack(&block_version),
            &mut ledger,
            &tx_out,
            &sender,
            &recipient.default_subaddress(),
            amount,
            fee,
            n_blocks + 1,
            &mut rng,
        );

        (adapt_hack(&tx), ledger)
    }

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
    fn test_validate_no_memo_exists() {
        let (tx, _) = create_test_tx(BlockVersion::ZERO);
        let tx_out = tx.prefix.outputs.first().unwrap();

        assert!(tx_out.e_memo.is_none());
        assert_eq!(validate_no_memo_exists(tx_out), Ok(()));

        let (tx, _) = create_test_tx(BlockVersion::ONE);
        let tx_out = tx.prefix.outputs.first().unwrap();

        assert!(tx_out.e_memo.is_some());
        assert_eq!(
            validate_no_memo_exists(tx_out),
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
        assert_eq!(validate_no_masked_token_id_exists(tx_out), Ok(()));

        let (tx, _) = create_test_tx(BlockVersion::TWO);
        let tx_out = tx.prefix.outputs.first().unwrap();

        assert!(!tx_out.masked_amount.masked_token_id.is_empty());
        assert_eq!(
            validate_no_masked_token_id_exists(tx_out),
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
    }

    #[test]
    // Should return InvalidRangeProof if a membership proof containing an invalid
    // Range.
    fn test_validate_membership_proofs_invalid_range_in_tx() {
        for block_version in BlockVersion::iterator() {
            let (mut tx, ledger) = create_test_tx(block_version);

            let highest_indices = tx.get_membership_proof_highest_indices();
            let root_proofs: Vec<TxOutMembershipProof> = adapt_hack(
                &ledger
                    .get_tx_out_proof_of_memberships(&highest_indices)
                    .expect("failed getting proofs"),
            );

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
            let mut root_proofs: Vec<TxOutMembershipProof> = adapt_hack(
                &ledger
                    .get_tx_out_proof_of_memberships(&highest_indices)
                    .expect("failed getting proofs"),
            );

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
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

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
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

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
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

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
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

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
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

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
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

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
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

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

    // FIXME: This test needs to involve a Tx with more than one output to make
    // sense
    #[test]
    #[ignore]
    fn test_global_validate_for_blocks_with_sorted_outputs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let fee = Mob::MINIMUM_FEE + 1;
        for block_version in BlockVersion::iterator() {
            // for block version < 3 it doesn't matter
            // for >= 3 it shall return an error about unsorted outputs
            let (tx, ledger) = create_test_tx_with_amount_and_comparer::<InverseTxOutputsOrdering>(
                block_version,
                INITIALIZE_LEDGER_AMOUNT - fee,
                fee,
            );

            let highest_indices = tx.get_membership_proof_highest_indices();
            let root_proofs: Vec<TxOutMembershipProof> = adapt_hack(
                &ledger
                    .get_tx_out_proof_of_memberships(&highest_indices)
                    .expect("failed getting proofs"),
            );

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
}
