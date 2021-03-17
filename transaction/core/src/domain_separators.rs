// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Domain separation tags for hash functions used in the MobileCoin transaction
//! protocol.
//!
//! Domain separation allows multiple distinct hash functions to be derived from
//! a single base function:   Hash_1(X) = Hash("Hash_1" || X),
//!   Hash_2(X) = Hash("Hash_2" || X),
//!   etc.
//!
//! Here, "Hash_1" and "Hash_2" are called domain separation tags. Tags should
//! uniquely identify the hash function within the protocol and may include the
//! protocol's version so that each derived hash function is independent of
//! others within the protocol and independent of hash functions in other
//! versions of the protocol.

/// Domain separator for Amount's value mask hash function.
pub const AMOUNT_VALUE_DOMAIN_TAG: &str = "mc_amount_value";

/// Domain separator for Amount's blinding mask hash function.
pub const AMOUNT_BLINDING_DOMAIN_TAG: &str = "mc_amount_blinding";

/// Domain separator for Bulletproof transcript.
pub const BULLETPROOF_DOMAIN_TAG: &str = "mc_bulletproof_transcript";

/// Domain separator for onetime key "hash_to_point" function.
pub const HASH_TO_POINT_DOMAIN_TAG: &str = "mc_onetime_key_hash_to_point";

/// Domain separator for onetime key "hash_to_scalar" function.
pub const HASH_TO_SCALAR_DOMAIN_TAG: &str = "mc_onetime_key_hash_to_scalar";

/// Domain separator for hashing a TxOut leaf node in a Merkle tree.
pub const TXOUT_MERKLE_LEAF_DOMAIN_TAG: &str = "mc_tx_out_merkle_leaf";

/// Domain separator for hashing internal hash values in a Merkle tree.
pub const TXOUT_MERKLE_NODE_DOMAIN_TAG: &str = "mc_tx_out_merkle_node";

/// Domain separator for hashing the "nil" value in a Merkle tree.
pub const TXOUT_MERKLE_NIL_DOMAIN_TAG: &str = "mc_tx_out_merkle_nil";

/// Domain separator for RingMLSAG's challenges.
pub const RING_MLSAG_CHALLENGE_DOMAIN_TAG: &str = "mc_ring_mlsag_challenge";

/// Domain separator for hashing the confirmation number
pub const TXOUT_CONFIRMATION_NUMBER_DOMAIN_TAG: &str = "mc_tx_out_confirmation_number";
