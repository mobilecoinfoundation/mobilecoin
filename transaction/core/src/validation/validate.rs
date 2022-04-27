// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Transaction validation.

extern crate alloc;

use alloc::{format, vec::Vec};

use super::error::{TransactionValidationError, TransactionValidationResult};
use crate::{
    constants::*,
    membership_proofs::{derive_proof_at_index, is_membership_proof_valid},
    tx::{Tx, TxOut, TxOutMembershipProof, TxPrefix},
    Amount, BlockVersion, TokenId,
};
use mc_common::HashSet;
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

    if block_version.signed_input_rules_are_supported() {
        validate_all_input_rules(block_version, tx)?;
    } else {
        validate_that_no_input_rules_exist(tx)?;
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
        validate_that_no_memo_exists(tx_out)?;
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
        validate_that_no_masked_token_id_exists(tx_out)?;
    }

    Ok(())
}

/// The transaction must have at least one input, and no more than the maximum
/// allowed number of inputs.
pub fn validate_number_of_inputs(
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
pub fn validate_number_of_outputs(
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
pub fn validate_ring_sizes(
    tx_prefix: &TxPrefix,
    ring_size: usize,
) -> TransactionValidationResult<()> {
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
pub fn validate_ring_elements_are_unique(tx_prefix: &TxPrefix) -> TransactionValidationResult<()> {
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
pub fn validate_ring_elements_are_sorted(tx_prefix: &TxPrefix) -> TransactionValidationResult<()> {
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
pub fn validate_inputs_are_sorted(tx_prefix: &TxPrefix) -> TransactionValidationResult<()> {
    check_sorted(
        &tx_prefix.inputs,
        |a, b| {
            !a.ring.is_empty() && !b.ring.is_empty() && a.ring[0].public_key < b.ring[0].public_key
        },
        TransactionValidationError::UnsortedInputs,
    )
}

/// Outputs must be sorted by the tx public key
pub fn validate_outputs_are_sorted(tx_prefix: &TxPrefix) -> TransactionValidationResult<()> {
    check_sorted(
        &tx_prefix.outputs,
        |a, b| a.public_key < b.public_key,
        TransactionValidationError::UnsortedOutputs,
    )
}

/// All key images within the transaction must be unique.
pub fn validate_key_images_are_unique(tx: &Tx) -> TransactionValidationResult<()> {
    check_unique(
        &tx.key_images(),
        TransactionValidationError::DuplicateKeyImages,
    )
}

/// All output public keys within the transaction must be unique.
pub fn validate_outputs_public_keys_are_unique(tx: &Tx) -> TransactionValidationResult<()> {
    check_unique(
        &tx.output_public_keys(),
        TransactionValidationError::DuplicateOutputPublicKey,
    )
}

/// All outputs have no memo (new-style TxOuts (Post MCIP #3) are rejected)
pub fn validate_that_no_memo_exists(tx_out: &TxOut) -> TransactionValidationResult<()> {
    if tx_out.e_memo.is_some() {
        return Err(TransactionValidationError::MemosNotAllowed);
    }
    Ok(())
}

/// All outputs have a memo (old-style TxOuts (Pre MCIP #3) are rejected)
pub fn validate_memo_exists(tx_out: &TxOut) -> TransactionValidationResult<()> {
    if tx_out.e_memo.is_none() {
        return Err(TransactionValidationError::MissingMemo);
    }
    Ok(())
}

/// All outputs have no masked token id (new-style TxOuts (Post MCIP #25) are
/// rejected)
pub fn validate_that_no_masked_token_id_exists(tx_out: &TxOut) -> TransactionValidationResult<()> {
    if !tx_out.masked_amount.masked_token_id.is_empty() {
        return Err(TransactionValidationError::MaskedTokenIdNotAllowed);
    }
    Ok(())
}

/// All outputs have a masked token id (old-style TxOuts (Pre MCIP #25) are
/// rejected)
pub fn validate_masked_token_id_exists(tx_out: &TxOut) -> TransactionValidationResult<()> {
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
    let rings = tx.prefix.get_input_rings();

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
pub fn validate_transaction_fee(tx: &Tx, minimum_fee: u64) -> TransactionValidationResult<()> {
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
pub fn validate_membership_proofs(
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

/// Any input rules imposed on the Tx must satisfied
pub fn validate_all_input_rules(
    block_version: BlockVersion,
    tx: &Tx,
) -> TransactionValidationResult<()> {
    for input in tx.prefix.inputs.iter() {
        if let Some(rules) = input.input_rules.as_ref() {
            rules.verify(block_version, tx)?;
        }
    }
    Ok(())
}

/// Any input rules imposed on the Tx must satisfied
pub fn validate_that_no_input_rules_exist(tx: &Tx) -> TransactionValidationResult<()> {
    for input in tx.prefix.inputs.iter() {
        if input.input_rules.is_some() {
            return Err(TransactionValidationError::InputRulesNotAllowed);
        }
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

// NOTE: There are unit tests of every validation function, which appear in
// transaction/core/tests/validation.rs.
//
// The reason that these appear there is,
// many of the tests use `mc-transaction-core-test-utils` which itself depends
// on `mc-ledger-db` and `mc-transaction-core`, and this creates a circular
// dependency which leads to build problems, if the unit tests appear in-line
// here.
//
// Please add tests for any new validation functions there. Thank you!
