// Copyright (c) 2018-2020 MobileCoin Inc.

//! In cryptography, several private keys can be derived from a single source of
//! entropy using a strong KDF (key derivation function).
//! This is sound, so long as the input-key-material to the KDF itself has
//! at least enough entropy as the length of any one of the derived keys.
//!
//! The RootIdentity object contains 32 bytes of "root entropy", used with HKDF
//! to produce the other mobilecoin private keys. This is useful an AccountKey
//! derived this way can be represented with a smaller amount of information.
//!
//! The other (fog-related) fields of RootIdentity are analogous to AccountKey.

use crate::{AccountKey, RootEntropyProblem};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{convert::From, hash::Hash};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use mc_crypto_hashes::Blake2b256;
use mc_crypto_keys::RistrettoPrivate;
use prost::Message;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

pub const TEST_FOG_AUTHORITY_FINGERPRINT: [u8; 4] = [9, 9, 9, 9];
pub const TEST_FOG_REPORT_KEY: &str = "";

/// A RootIdentity contains 32 bytes of root entropy (for deriving private keys
/// using a KDF), together with any fog data for the account.
#[derive(Clone, PartialEq, Eq, Hash, Message, Serialize, Deserialize)]
pub struct RootIdentity {
    /// Root entropy used to derive a user's private keys.
    #[prost(bytes, tag = 1)]
    pub root_entropy: Vec<u8>,
    /// Fog report url
    #[prost(string, tag = 2)]
    pub fog_url: String,
    /// Fog report id
    #[prost(string, tag = 3)]
    pub fog_report_id: String,
    /// Fog authority fingerprint
    #[prost(bytes, tag = 4)]
    pub fog_authority_fingerprint: Vec<u8>,
}

impl RootIdentity {
    /// Generate a random root identity with a specific fog url configured
    pub fn random<T: RngCore + CryptoRng>(rng: &mut T, fog_url: Option<&str>) -> Self {
        let mut root_entropy = [0u8; 32];
        // Filter out bad root entropies
        // TODO: Break after 100 tries and fail?
        loop {
            rng.fill_bytes(&mut root_entropy);
            if crate::check_root_entropy(&root_entropy[..]).is_ok() {
                break;
            }
        }

        let mut result = Self {
            root_entropy: root_entropy.to_vec(),
            fog_url: Default::default(),
            fog_report_id: Default::default(),
            fog_authority_fingerprint: Default::default(),
        };

        if let Some(fog_url) = fog_url {
            result.fog_url = fog_url.to_string();
            // FIXME: Require explicit args here as well?
            result.fog_report_id = TEST_FOG_REPORT_KEY.to_string();
            result.fog_authority_fingerprint = TEST_FOG_AUTHORITY_FINGERPRINT.to_vec();
        }

        result
    }

    /// Check root entropy for "obvious" statistical problems or blacklisted values.
    ///
    /// This function SHOULD be called before turning RootIdentity into AccountKey.
    ///
    /// Root entropy that does not return Ok from this check SHOULD be rejected,
    /// *during account creation*.
    /// During *loading of a pre-existing account*, which may already have money on it,
    /// the root entropy CANNOT be rejected -- we must still generate the account key
    /// so that the user can access funds. But we should perhaps show a warning so that
    /// they can learn to change their private keys.
    ///
    /// This policy allows that new, more restrictive, tests and blacklist values can be added
    /// to the logic of this function, as a non-breaking change.
    pub fn check_root_entropy(&self) -> Result<(), RootEntropyProblem> {
        crate::check_root_entropy(&self.root_entropy)
    }
}

/// Derive an AccountKey from RootIdentity
impl From<&RootIdentity> for AccountKey {
    fn from(src: &RootIdentity) -> Self {
        assert!(src.root_entropy.len() >= 32, "Root identity with less than 32 bytes of entropy is invalid and cannot be used to create AccountKey");
        let spend_private_key =
            RistrettoPrivate::from(root_identity_hkdf_helper(&src.root_entropy, b"spend"));
        let view_private_key =
            RistrettoPrivate::from(root_identity_hkdf_helper(&src.root_entropy, b"view"));
        AccountKey::new_with_fog(
            &spend_private_key,
            &view_private_key,
            src.fog_url.clone(),
            src.fog_report_id.clone(),
            src.fog_authority_fingerprint.clone(),
        )
    }
}

/// Construct fogless RootIdentity from [u8;32]
impl From<&[u8; 32]> for RootIdentity {
    fn from(src: &[u8; 32]) -> Self {
        Self {
            root_entropy: src.to_vec(),
            fog_url: Default::default(),
            fog_report_id: Default::default(),
            fog_authority_fingerprint: Default::default(),
        }
    }
}

// Helper function for using hkdf to derive a key
#[inline]
fn root_identity_hkdf_helper(ikm: &[u8], info: &[u8]) -> Scalar {
    let mut result = [0u8; 32];
    let (_, hk) = Hkdf::<Blake2b256>::extract(None, ikm);

    // expand cannot fail because 32 bytes is a valid keylength for blake2b/256
    hk.expand(info, &mut result)
        .expect("buffer size arithmetic is wrong");

    // Now we reduce the result modulo group order. Cryptonote functions using
    // the `scalar_from_bytes` macro require this because the macro uses
    // `Scalar::from_canonical_bytes` rather than `Scalar::from_bits` or
    // `Scalar::from_bytes_mod_order`. It will returns an error if we don't make
    // the representation canonical
    Scalar::from_bytes_mod_order(result)
}

#[cfg(test)]
mod testing {
    use super::*;
    use core::convert::TryInto;
    use yaml_rust::{Yaml, YamlLoader};

    #[test]
    // Deserializing should recover a serialized RootIdentity.
    fn mc_util_serial_roundtrip_root_identity() {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let root_id = RootIdentity::random(&mut rng, None);
            let ser = mc_util_serial::serialize(&root_id).unwrap();
            let result: RootIdentity = mc_util_serial::deserialize(&ser).unwrap();
            assert_eq!(root_id, result);

            let root_id = RootIdentity::random(&mut rng, Some("example.com"));
            let ser = mc_util_serial::serialize(&root_id).unwrap();
            let result: RootIdentity = mc_util_serial::deserialize(&ser).unwrap();
            assert_eq!(root_id, result);
        })
    }

    #[test]
    fn test_acct_priv_keys_from_root_entropy() {
        let yaml = YamlLoader::load_from_str(include_str!(
            "../../test-data/transaction/identity/acct_priv_keys_from_root_entropy.yaml"
        ))
        .unwrap();

        for test in yaml[0].clone() {
            let root_entropy = yaml_as_byte_array(&test["root_entropy"]);
            let view_private_key = yaml_as_byte_array(&test["view_private_key"]);
            let spend_private_key = yaml_as_byte_array(&test["spend_private_key"]);

            let root32: [u8; 32] = root_entropy.as_slice().try_into().unwrap();
            let account_key = AccountKey::from(&RootIdentity::from(&root32));
            assert_eq!(
                account_key.view_private_key().to_bytes(),
                view_private_key.as_slice()
            );
            assert_eq!(
                account_key.spend_private_key().to_bytes(),
                spend_private_key.as_slice()
            );
        }
    }

    fn yaml_as_byte_array(yaml: &Yaml) -> Vec<u8> {
        yaml.clone()
            .into_iter()
            .map(|elem| elem.as_i64().unwrap().try_into().unwrap())
            .collect::<Vec<_>>()
    }
}
