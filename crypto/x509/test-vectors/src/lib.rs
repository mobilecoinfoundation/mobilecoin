// Copyright (c) 2018-2020 MobileCoin Inc.

//! Helper functions intended to return canned certificate data

use mc_crypto_keys::{DistinguishedEncoding, Ed25519Pair, Ed25519Private};
use std::{fs, path::PathBuf};
use x509_parser::pem;

/// Retrieve a pathbuf for a file containing a PEM string
fn base_path() -> PathBuf {
    let mut path = PathBuf::from(env!("OUT_DIR"));
    path.push("openssl");
    path
}

fn get_chain(name: &str) -> String {
    let mut path = base_path();
    path.push(name);
    path.set_extension("pem");
    fs::read_to_string(path).expect("Could not read certificate chain")
}

fn get_leaf_key(name: &str) -> Ed25519Pair {
    let mut path = base_path();
    path.push(name);
    path.set_extension("key");

    let pem_string = fs::read_to_string(path).expect("Could not read certificate chain");
    let (_, pem_data) =
        pem::parse_x509_pem(pem_string.as_ref()).expect("Could not parse PEM string");

    let privkey = Ed25519Private::try_from_der(&pem_data.contents)
        .expect("Could not construct private key from key DER bytes");
    Ed25519Pair::from(privkey)
}

/// Retrieve a PEM string containing the root authority used in tests with valid
/// roots.
pub fn ok_rsa_head() -> String {
    get_chain("ok_rsa_head")
}

/// Retrieve a PEM string containing an entire RSA certificate hierarchy with
/// multiple branching intermediate certificates.
///
/// This is intended to be the stickiest test of out-of-order chains.
pub fn ok_rsa_tree() -> String {
    get_chain("ok_rsa_tree")
}

/// Retrieve a PEM string containing a chain of 2 RSA certificates and an
/// Ed25519 leaf certificate.
///
/// The leaf certificate's keypair is also returned.
///
/// This is intended to feed a positive test of the cert.
pub fn ok_rsa_chain_25519_leaf() -> (String, Ed25519Pair) {
    (
        get_chain("ok_rsa_chain_25519_leaf"),
        get_leaf_key("ok_rsa_chain_25519_leaf"),
    )
}

/// Retrieve a PEM string containing a chain of 9 RSA certificates and an
/// Ed25519 leaf certificate.
///
/// The leaf certificate's keypair is also returned.
///
/// This is intended to test a CA chain's max-depth limits.
pub fn ok_rsa_chain_depth_10() -> (String, Ed25519Pair) {
    (
        get_chain("ok_rsa_chain_depth_10"),
        get_leaf_key("ok_rsa_chain_depth_10"),
    )
}

/// Retrieve a PEM string containing a chain of 2 RSA certificates and an
/// Ed25519 leaf certificate, albeit out of order (leaf, CA, intermediate).
///
/// This is a simplified version of [`ok_rsa_tree()`].
pub fn ok_rsa_out_of_order() -> (String, Ed25519Pair) {
    (
        get_chain("ok_rsa_out_of_order"),
        get_leaf_key("ok_rsa_out_of_order"),
    )
}

/// Retrieve a PEM string containing a chain of 2 RSA certificate and an Ed25519
/// leaf certificate that is not valid yet.
pub fn fail_leaf_too_soon() -> (String, Ed25519Pair) {
    (
        get_chain("fail_leaf_too_soon"),
        get_leaf_key("fail_leaf_too_soon"),
    )
}

/// Retrieve a PEM string containing a chain of 2 RSA certificate and an Ed25519
/// leaf certificate that has expired.
pub fn fail_leaf_expired() -> (String, Ed25519Pair) {
    (
        get_chain("fail_leaf_expired"),
        get_leaf_key("fail_leaf_expired"),
    )
}

/// Retrieve a PEM string containing a root RSA certificate and an Ed25519 leaf
/// certificate, without an intermediate authority.
pub fn fail_missing_link() -> (String, Ed25519Pair) {
    (
        get_chain("fail_missing_link"),
        get_leaf_key("fail_missing_link"),
    )
}

/// Retrieve a PEM string containing an intermeidate RSA certificate and an
/// Ed25519 leaf certificate, without the self-signed root authority.
pub fn fail_missing_head() -> (String, Ed25519Pair) {
    (
        get_chain("fail_missing_head"),
        get_leaf_key("fail_missing_head"),
    )
}

#[cfg(test)]
mod test {
    use super::*;

    /// See if [`ok_rsa_head()`] returns any data
    #[test]
    fn ok_rsa_head_has_data() {
        assert!(!ok_rsa_head().is_empty());
    }

    /// Test to see if [`ok_rsa_chain_25519_leaf()`] returns any data
    #[test]
    fn ok_rsa_chain_25519_leaf_has_data() {
        let (chainpem, _) = ok_rsa_chain_25519_leaf();
        assert!(!chainpem.is_empty());
    }

    /// Test to see if [`ok_rsa_chain_depth_10()`] returns any data
    #[test]
    fn ok_rsa_chain_depth_10_has_data() {
        let (chainpem, _) = ok_rsa_chain_depth_10();
        assert!(!chainpem.is_empty());
    }

    /// Test to see if [`ok_rsa_tree()`] returns any data
    #[test]
    fn ok_rsa_tree_has_data() {
        assert!(!ok_rsa_tree().is_empty());
    }

    /// Test to see if [`ok_rsa_out_of_order()`] returns any data
    #[test]
    fn ok_rsa_out_of_order_has_data() {
        let (chainpem, _) = ok_rsa_out_of_order();
        assert!(!chainpem.is_empty());
    }

    /// Test to see if [`fail_leaf_too_soon()`] returns any data
    #[test]
    fn fail_leaf_too_soon_has_data() {
        let (chainpem, _) = fail_leaf_too_soon();
        assert!(!chainpem.is_empty());
    }

    /// Test to see if [`fail_leaf_expired()`] returns any data
    #[test]
    fn fail_leaf_expired_has_data() {
        let (chainpem, _) = fail_leaf_expired();
        assert!(!chainpem.is_empty());
    }

    /// Test to see if [`fail_missing_link()`] returns any data
    #[test]
    fn fail_missing_link_has_data() {
        let (chainpem, _) = fail_missing_link();
        assert!(!chainpem.is_empty());
    }

    /// Test to see if [`fail_missing_head()`] returns any data
    #[test]
    fn fail_missing_head_has_data() {
        let (chainpem, _) = fail_missing_head();
        assert!(!chainpem.is_empty());
    }
}
