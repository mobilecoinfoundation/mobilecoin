// Copyright (c) 2018-2020 MobileCoin Inc.

//! Helper functions intended to return canned certificate data

/// Retrieve a PEM string containing the root authority used in tests with valid
/// roots.
pub fn ok_rsa_head() -> String {}

/// Retrieve a PEM string containing a chain of 2 RSA certificates and an
/// Ed25519 leaf certificate.
///
/// The leaf certificate's keypair is also returned.
///
/// This is intended to feed a positive test of the cert.
pub fn ok_rsa_chain_25519_leaf() -> (String, Ed25519Pair) {}

/// Retrieve a PEM string containing a chain of 9 RSA certificates and an
/// Ed25519 leaf certificate.
///
/// The leaf certificate's keypair is also returned.
///
/// This is intended to test a CA chain's max-depth limits.
pub fn ok_rsa_chain_depth_10() -> (String, Ed25519Pair) {}

/// Retrieve a PEM string containing an entire RSA certificate hierarchy with
/// multiple branching intermediate certificates.
///
/// This is intended to be the stickiest test of out-of-order chains.
pub fn ok_rsa_tree() -> String {}

/// Retrieve a PEM string containing a chain of 2 RSA certificates and an
/// Ed25519 leaf certificate, albeit out of order (leaf, CA, intermediate).
///
/// This is a simplified version of [`ok_rsa_tree()`].
pub fn ok_rsa_out_of_order() -> (String, Ed25519Pair) {}

/// Retrieve a PEM string containing a chain of 2 RSA certificate and an Ed25519
/// leaf certificate that is not valid yet.
pub fn fail_leaf_too_soon() -> (String, Ed25519Pair) {}

/// Retrieve a PEM string containing a chain of 2 RSA certificate and an Ed25519
/// leaf certificate that has expired.
pub fn fail_leaf_expired() -> (String, Ed25519Pair) {}

/// Retrieve a PEM string containing a root RSA certificate and an Ed25519 leaf
/// certificate, without an intermediate authority.
pub fn fail_missing_link() -> (String, Ed25519Pair) {}

/// Retrieve a PEM string containing an intermeidate RSA certificate and an
/// Ed25519 leaf certificate, without the self-signed root authority.
pub fn fail_missing_head() -> (String, Ed25519Pair) {}
