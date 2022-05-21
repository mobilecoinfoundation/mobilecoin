// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Domain separation tags for hash functions used in the MobileCoin amount and
//! MLSAG protocols.
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

/// Domain separator for onetime key "hash_to_point" function.
pub const HASH_TO_POINT_DOMAIN_TAG: &str = "mc_onetime_key_hash_to_point";

/// Domain separator for onetime key "hash_to_scalar" function.
pub const HASH_TO_SCALAR_DOMAIN_TAG: &str = "mc_onetime_key_hash_to_scalar";

/// Domain separator for RingMLSAG's challenges.
pub const RING_MLSAG_CHALLENGE_DOMAIN_TAG: &str = "mc_ring_mlsag_challenge";
