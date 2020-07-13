// Copyright (c) 2018-2020 MobileCoin Inc.

#![allow(clippy::if_same_then_else)]

extern crate alloc;

mod errors;

use crate::{
    domain_separators::{
        TXOUT_MERKLE_LEAF_DOMAIN_TAG, TXOUT_MERKLE_NIL_DOMAIN_TAG, TXOUT_MERKLE_NODE_DOMAIN_TAG,
    },
    membership_proofs::errors::Error,
    range::Range,
    tx::{TxOut, TxOutMembershipHash, TxOutMembershipProof},
};
use alloc::vec::Vec;
use blake2::digest::Input;
use core::convert::TryInto;
pub use errors::Error as MembershipProofError;
use mc_common::HashMap;
use mc_crypto_digestible::Digestible;
use mc_crypto_hashes::Blake2b256;

lazy_static! {
    pub static ref NIL_HASH: [u8; 32] = hash_nil();
}

/// Merkle tree hash function for a leaf node.
pub fn hash_leaf(tx_out: &TxOut) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.input(&TXOUT_MERKLE_LEAF_DOMAIN_TAG);
    tx_out.digest(&mut hasher);
    hasher.result().try_into().unwrap()
}

/// Merkle tree hash function for an internal node.
pub fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.input(&TXOUT_MERKLE_NODE_DOMAIN_TAG);
    hasher.input(left);
    hasher.input(right);
    hasher.result().try_into().unwrap()
}

/// Merkle tree Hash function for hashing a "nil" value.
fn hash_nil() -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.input(&TXOUT_MERKLE_NIL_DOMAIN_TAG);
    hasher.result().try_into().unwrap()
}

/// Validates a proof-of-membership.
///
/// # Arguments
/// * `tx_out` - A `TxOut`.
/// * `proof` - A proof that `tx_out` is in the set of `TxOut`s.
/// * `known_root_hash` - The known root hash of the Merkle tree.
///
/// Returns a bool indicating if the proof is valid, or an Error if something went wrong
/// while evaluating the proof.
//
pub fn is_membership_proof_valid(
    tx_out: &TxOut,
    proof: &TxOutMembershipProof,
    known_root_hash: &[u8; 32],
) -> Result<bool, Error> {
    if proof.index > proof.highest_index {
        return Ok(false);
    }

    // * The proof must contain the correct leaf hash for the specified index.
    let leaf = Range::new(proof.index, proof.index)
        .expect("A Range containing a single value is always well-formed.");

    let range_to_hash: HashMap<Range, [u8; 32]> = proof
        .elements
        .iter()
        .map(|element| (element.range, *element.hash.as_ref()))
        .collect();

    if let Some(leaf_hash) = range_to_hash.get(&leaf) {
        if *leaf_hash != hash_leaf(tx_out) {
            // Proof contains incorrect leaf hash.
            return Err(Error::IncorrectLeafHash(leaf.from));
        }
    } else {
        // Proof does not contain a leaf hash for `tx_out`.
        return Err(Error::MissingLeafHash(leaf.from));
    }

    // * The root hash of the proof must match the known root_hash.
    let mut ranges: Vec<&Range> = range_to_hash.keys().collect();
    ranges.sort();

    let root_range = ranges.last().expect("`ranges` should be non-empty.");
    let root_hash = range_to_hash
        .get(root_range)
        .expect("`root_range` should be a key.");

    if *root_hash != *known_root_hash {
        // Incorrect root hash.
        return Ok(false);
    }

    if proof.highest_index > root_range.to {
        return Ok(false);
    }

    // * All internal node's hashes between leaf and root must be recomputable from their children's hashes.
    let ranges_containing_tx_out: Vec<&Range> = ranges
        .iter()
        .cloned()
        .filter(|range| range.from <= proof.index && proof.index <= range.to)
        .collect();

    for range in &ranges_containing_tx_out {
        let hash = range_to_hash
            .get(range)
            .expect("range_to_hash must contain range");
        if range.from != range.to {
            // Internal Node.
            let mid: u64 = (range.from + range.to) / 2;

            // Left child.
            let left_child_range = Range::new(range.from, mid)?;
            let left_child_hash = match range_to_hash.get(&left_child_range) {
                Some(hash) => hash,
                None => {
                    // Proof does not contain a required hash.
                    return Ok(false);
                }
            };

            // Right child.
            let right_child_range = Range::new(mid + 1, range.to)?;
            let right_child_hash = match range_to_hash.get(&right_child_range) {
                Some(hash) => hash,
                None => {
                    // Proof does not contain a required hash.
                    return Ok(false);
                }
            };

            let expected_hash = hash_nodes(left_child_hash, right_child_hash);
            if *hash != expected_hash {
                // Proof contains an incorrect hash value.
                return Ok(false);
            }
        }
    }

    Ok(true)
}

/// Compute the root hash at the time the TxOut was added.
///
/// This can be used to "roll back" a proof made when the tree contains `n` TxOuts to produce a proof
/// when the tree contained `m < n` elements.
///
/// # Arguments
/// * `initial_proof` - Proof-of-membership for the TxOut at a given index. Assumed to be valid.
///
/// # Returns
/// Returns a proof for TxOut where the TxOut is the last member added to the tree.
pub fn derive_proof_at_index(
    initial_proof: &TxOutMembershipProof,
) -> Result<TxOutMembershipProof, Error> {
    // Index of the TxOut referenced by the proof.
    let index: u64 = initial_proof.index;

    // Range of indices in the smallest full binary tree that contains `index`.
    let derived_root_range: Range = {
        let num_leaves_full_tree_opt = (index + 1).checked_next_power_of_two();
        if num_leaves_full_tree_opt.is_none() {
            return Err(Error::CapacityExceeded);
        }

        let num_leaves_full_tree = num_leaves_full_tree_opt.unwrap();
        Range::new(0, num_leaves_full_tree - 1)
    }?;

    // Elements of the derived proof.
    let mut derived_elements: HashMap<Range, [u8; 32]> = HashMap::default();

    // This assumes that `elements` is sorted from smallest to largest, so that hashes are
    // computed "bottom up".
    for element in &initial_proof.elements {
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
            // Recompute its hash from its child ranges.
            let mid: u64 = (element.range.from + element.range.to) / 2;

            // Left child.
            let left_child_hash = {
                let left_child_range = Range::new(element.range.from, mid)?;
                *derived_elements
                    .get(&left_child_range)
                    .expect("Child range should already exist.")
            };

            // Right child.
            let right_child_hash = {
                let right_child_range = Range::new(mid + 1, element.range.to)?;
                *derived_elements
                    .get(&right_child_range)
                    .expect("Child range should already exist.")
            };

            TxOutMembershipHash::from(hash_nodes(&left_child_hash, &right_child_hash))
        };
        derived_elements.insert(element.range, *hash.as_ref());
    }

    Ok(TxOutMembershipProof::new(index, index, derived_elements))
}

#[cfg(test)]
mod tests {
    // TODO: the tests for derive_proof_at_index are currently in ledger_db/tx_out_store.rs.
}
