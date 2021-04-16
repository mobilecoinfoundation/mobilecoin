// Copyright (c) 2018-2021 The MobileCoin Foundation

#![allow(clippy::if_same_then_else)]

extern crate alloc;

use crate::{
    domain_separators::{
        TXOUT_MERKLE_LEAF_DOMAIN_TAG, TXOUT_MERKLE_NIL_DOMAIN_TAG, TXOUT_MERKLE_NODE_DOMAIN_TAG,
    },
    membership_proofs::errors::{Error, RangesNotAdjacentError},
    tx::{TxOut, TxOutMembershipElement, TxOutMembershipHash, TxOutMembershipProof},
};
use alloc::vec::Vec;
use blake2::digest::Update;
use core::convert::TryInto;

use mc_crypto_hashes::Blake2b256;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

mod errors;
mod range;

pub use errors::Error as MembershipProofError;
pub use range::{Range, RangeError};

lazy_static! {
    pub static ref NIL_HASH: [u8; 32] = hash_nil();
}

/// Merkle tree hash function for a leaf node.
pub fn hash_leaf(tx_out: &TxOut) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(&TXOUT_MERKLE_LEAF_DOMAIN_TAG);
    hasher.update(&tx_out.hash());
    hasher.result().try_into().unwrap()
}

/// Merkle tree hash function for an internal node.
pub fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(&TXOUT_MERKLE_NODE_DOMAIN_TAG);
    hasher.update(left);
    hasher.update(right);
    hasher.result().try_into().unwrap()
}

/// Merkle tree Hash function for hashing a "nil" value.
fn hash_nil() -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(&TXOUT_MERKLE_NIL_DOMAIN_TAG);
    hasher.result().try_into().unwrap()
}

/// Compose two adjacent TxOutMembershipElements into a larger
/// TxOutMembershipElement. Fails if they are not actually adjacent.
///
/// This function can be used to validate a Merkle proof from the bottom up
/// in a side-channel resistant way. The elements lowest in the tree should be
/// combined, then the result combined with the next highest element etc.
/// finally getting a range and hash at the top. This is then checked against
/// the expected hash of the root element.
///
/// This function MUST not branch except to immediately return an error
///
/// Precondition: a and b are well-formed ranges, a.from <= a.to, b.from <= b.to
/// It is the callers job to check that.
///
/// Arguments:
/// * a: TxOutMembershipElement to be combined
/// * b: TxOutMembershipElement to be combined with a, and which should be its
///   left or right sibling
///
/// Returns:
/// * A TxOutMembershipElement for the parent of a and b, with the implied hash
///   value.
/// * An error if a and b were not adjacent, which implies that the merkle proof
///   was badly structured. This error can be mapped to e.g.
///   Error::UnexpectedMembershipElement and the caller can provide context.
pub fn compose_adjacent_membership_elements(
    a: &TxOutMembershipElement,
    b: &TxOutMembershipElement,
) -> Result<TxOutMembershipElement, RangesNotAdjacentError> {
    // a is to the left if a.to matches b.from
    // a is to the right if a.from matches b.to
    // Because these are inclusive [,] ranges and not half-open ranges [,)
    // we have to add one when checking if they match.
    // wrapping_add is used to avoid creating a branch in the generated assembly
    let a_is_left = (a.range.to.wrapping_add(1)).ct_eq(&b.range.from);
    let b_is_left = (b.range.to.wrapping_add(1)).ct_eq(&a.range.from);
    // If neither is to the left according to above test, then the merkle proof
    // isn't structured correctly and we can early return with an "unexpected
    // merkle proof" element of some kind. The client can easily ensure that the
    // merkle proof is well-structured. If both are to the left according to
    // this test, then one of the ranges must be reversed, contrary to the
    // precondition.
    if !bool::from(a_is_left ^ b_is_left) {
        return Err(RangesNotAdjacentError);
    }

    // Initialize the result as if a is the left and b is right,
    // then use conditional_assign to fix it if not.
    // The point of this is to get conditional logic without branching,
    // subtle::conditional_assign is assumed to be side-channel resistant
    let mut result = TxOutMembershipElement {
        range: Range {
            from: a.range.from,
            to: b.range.to,
        },
        hash: Default::default(),
    };
    result
        .range
        .from
        .conditional_assign(&b.range.from, b_is_left);
    result.range.to.conditional_assign(&a.range.to, b_is_left);

    // Initialize left and right as if a is the left and b is the right,
    // then use conditional_assign to fix it if not.
    let mut left = a.hash.0;
    let mut right = b.hash.0;
    conditional_assign_32_bytes(&mut left, &b.hash.0, b_is_left);
    conditional_assign_32_bytes(&mut right, &a.hash.0, b_is_left);

    result.hash.0 = hash_nodes(&left, &right);
    Ok(result)
}

// Helper: Conditionally assign to [u8; 32]
//
// It seems subtle doesn't implement ConditionallySelectable on [u8; 32], not
// sure why, so we can't just use the conditional_assign function from that API.
//
// If this is slow then we can later used a faster implementation, but it
// probably won't be that slow.
fn conditional_assign_32_bytes(target: &mut [u8; 32], src: &[u8; 32], cond: Choice) {
    for idx in 0..32 {
        target[idx].conditional_assign(&src[idx], cond);
    }
}

/// Checks that a proof of membership is well-formed, and returns the hash that
/// it implies for the root. This hash should then be checked against known root
/// hash value.
///
/// Errors if:
/// - Any proof elements have invalid ranges (from and to out of order)
/// - The first element is missing or its range doesn't match proof.index
/// - Any of the proof elements could not be combined with result of combining
///   predecessors
///
/// This function MUST NOT branch except to immediately return an error
///
/// Note: This is pub in order to allow that it can be used in debugging
/// assertions elsewhere. This could simply be a member function on
/// TxOutMembershipProof, but that would require hash_nodes function to be in
/// scope in that module, so for now we didn't do that.
pub fn compute_implied_merkle_root(
    proof: &TxOutMembershipProof,
) -> Result<TxOutMembershipElement, Error> {
    // All Ranges contained in the proof must be valid. An invalid Range could be
    // created by deserializing invalid bytes.
    if proof.elements.iter().any(|e| e.range.from > e.range.to) {
        return Err(Error::RangeError(RangeError {}));
    }

    // The first element should correspond to proof.index in a well-formed proof
    let first = proof
        .elements
        .first()
        .ok_or(Error::MissingLeafHash(proof.index))?
        .clone();
    if first.range.from != proof.index || first.range.to != proof.index {
        return Err(Error::MissingLeafHash(proof.index));
    }

    // Try to fold subsequent elements together with the first element,
    // combining them using `combine_adjacent_membership_elements`.
    // idx is used only to provide context for the error message
    let implied_root = proof.elements[1..].iter().enumerate().try_fold(
        first,
        |prev, (idx, next)| -> Result<TxOutMembershipElement, Error> {
            compose_adjacent_membership_elements(&prev, next)
                .map_err(|_| Error::UnexpectedMembershipElement(idx + 1))
        },
    )?;

    // At this point, we could check that implied_root.range.to =
    // proof.highest_index, or that -1, or something, but I'm not sure at this
    // moment what exactly the right test is, and I don't think we really need this,
    // it would be mainly a debugging aid. For security we only need to check that
    // the implied root hash matches what the enclave expects.
    // We could similarly contemplate testing that implied_root.range.from == 0, but
    // this is omitted for now.

    Ok(implied_root)
}

/// Validates a proof-of-membership.
///
/// # Arguments
/// * `tx_out` - A `TxOut`.
/// * `proof` - A proof that `tx_out` is in the set of `TxOut`s.
/// * `known_root_hash` - The known root hash of the Merkle tree.
///
/// Returns a bool indicating if the proof is valid, or an Error if something
/// went wrong while evaluating the proof.
///
/// This function MUST NOT branch except to immediately return an error
pub fn is_membership_proof_valid(
    tx_out: &TxOut,
    proof: &TxOutMembershipProof,
    known_root_hash: &[u8; 32],
) -> Result<bool, Error> {
    if proof.index > proof.highest_index {
        return Err(Error::HighestIndexMismatch);
    }

    // The first element must be the leaf hash corresponding to the proof index
    let first = proof
        .elements
        .first()
        .ok_or(Error::MissingLeafHash(proof.index))?;
    if first.range.from != proof.index || first.range.to != proof.index {
        return Err(Error::MissingLeafHash(proof.index));
    }
    // The first element hash must match the tx_out
    if !bool::from(first.hash.as_ref().ct_eq(&hash_leaf(tx_out))) {
        return Err(Error::IncorrectLeafHash(first.range.from));
    }

    // Compute the implied root hash, or an error if this can't be done
    let implied_root = compute_implied_merkle_root(proof)?;

    if 0 != implied_root.range.from {
        return Err(Error::RootNotCoveringZero);
    }

    if proof.highest_index > implied_root.range.to {
        return Err(Error::HighestIndexMismatch);
    }

    // Check if the implied root hash matches the known root hash
    // If it doesn't, we return false, but not a rust error.
    Ok(bool::from(
        implied_root.hash.as_ref().ct_eq(known_root_hash),
    ))
}

/// Compute the root hash at the time the TxOut was added.
///
/// This can be used to "roll back" a proof made when the tree contains `n`
/// TxOuts to produce a proof when the tree contained `m < n` elements.
///
/// # Arguments
/// * `initial_proof` - Proof-of-membership for the TxOut at a given index.
///   Assumed to be valid.
///
/// # Returns
/// Returns a proof for TxOut where the TxOut is the last member added to the
/// tree.
pub fn derive_proof_at_index(
    initial_proof: &TxOutMembershipProof,
) -> Result<TxOutMembershipProof, Error> {
    // Index of the TxOut referenced by the proof.
    let index: u64 = initial_proof.index;

    // Range of indices in the smallest full binary tree that contains `index`.
    let derived_root_range: Range = {
        let num_leaves_full_tree_opt = (index + 1).checked_next_power_of_two();
        if num_leaves_full_tree_opt.is_none() {
            return Err(Error::NumericLimitsExceeded);
        }

        let num_leaves_full_tree = num_leaves_full_tree_opt.unwrap();
        Range::new(0, num_leaves_full_tree - 1)
    }?;

    // Elements of the derived proof.
    let mut derived_elements = Vec::<TxOutMembershipElement>::default();

    // This assumes that `elements` is in the correct order to be combined.
    for (element_idx, element) in initial_proof.elements.iter().enumerate() {
        if element.range > derived_root_range {
            // This range is not part of the derived proof.
            continue;
        }

        let hash = if element.range.from > index {
            // This range exceeds `index`.
            TxOutMembershipHash::from(hash_nil())
        } else if element.range.from == element.range.to {
            // A leaf. Re-use the hash supplied by the input proof.
            element.hash.clone()
        } else if element.range.to <= index {
            // This range is unchanged. Re-use the supplied hash.
            element.hash.clone()
        } else {
            // An internal node that contains `index`.
            // This is unexpected, none of the proof elements should cover index.
            return Err(Error::UnexpectedMembershipElement(element_idx));
        };
        derived_elements.push(TxOutMembershipElement {
            range: element.range,
            hash,
        });
    }

    Ok(TxOutMembershipProof::new(index, index, derived_elements))
}

#[cfg(test)]
mod tests {
    // TODO: the tests for derive_proof_at_index are currently in
    // ledger_db/tx_out_store.rs.
}
