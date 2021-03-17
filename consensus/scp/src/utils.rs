// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::core_types::SlotIndex;
use bigint::U256;
use mc_common::fast_hash;

/// A "salted" Keccak hash function, parametrized by slot, round, and an extra
/// value.
///
/// # Arguments
/// * `slot_index`
/// * `extra_salt`
/// * `round_index`
/// * `bytes` - The bytes to hash.
///
/// # Returns
/// 256-bit unsigned value
/// Keccak(slot_index || extra_salt || round_index || bytes), where || denotes
/// concatenation,
pub fn slot_round_salted_keccak(
    slot_index: SlotIndex,
    extra_salt: u8,
    round_index: u32,
    bytes: &[u8],
) -> U256 {
    let slot_index_bytes: [u8; 8] = slot_index.to_be_bytes();
    let round_index_bytes: [u8; 4] = round_index.to_be_bytes();
    let extra: [u8; 1] = [extra_salt]; // Wrap this in an array so that concatenation is more consistent.

    let mut concatenation: Vec<u8> = vec![];
    concatenation.extend(slot_index_bytes.iter());
    concatenation.extend(extra.iter());
    concatenation.extend(round_index_bytes.iter());
    concatenation.extend(bytes.iter());

    U256::from(fast_hash(&concatenation))
}
