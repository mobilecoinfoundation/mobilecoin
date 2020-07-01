// Copyright (c) 2018-2020 MobileCoin Inc.

//! Derived Account Identity
//!
//! Identity in the MobileCoin cryptosystem consists of 64 bytes of private key data.
//! It is convenient to derive an identity from a smaller set of bytes, representing
//! less than 64 bytes of entropy.
//!

use core::hash::Hash;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use mc_crypto_keys::RistrettoPrivate;
use mc_transaction_core::{account_keys::AccountKey, blake2b_256::Blake2b256};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::convert::From;

pub const TEST_FOG_AUTHORITY_FINGERPRINT: [u8; 4] = [9, 9, 9, 9];
pub const TEST_FOG_REPORT_KEY: &str = "";

/// A RootIdentity is used to quickly derive an AccountKey from 32 bytes of entropy
/// for testing purposes. It should not be used to derive AccountKeys outside of a
/// development environment.
#[derive(Clone, PartialEq, Eq, Hash, Default, Debug, Serialize, Deserialize)]
pub struct RootIdentity {
    /// Root entropy used to derive a user's private keys.
    pub root_entropy: [u8; 32],
    /// User's account server, if any.
    pub fog_url: Option<String>,
}

impl RootIdentity {
    /// Generate a random root identity with a specific account server configured
    pub fn random<T: RngCore + CryptoRng>(rng: &mut T, fog_url: Option<&str>) -> Self {
        let mut root_entropy = [0u8; 32];
        rng.fill_bytes(&mut root_entropy);

        Self {
            root_entropy,
            fog_url: fog_url.map(|x| x.to_string()),
        }
    }
}

/// Derive an AccountKey from RootIdentity
impl From<&RootIdentity> for AccountKey {
    fn from(src: &RootIdentity) -> Self {
        let spend_private_key =
            RistrettoPrivate::from(root_identity_hkdf_helper(&src.root_entropy, b"spend"));
        let view_private_key =
            RistrettoPrivate::from(root_identity_hkdf_helper(&src.root_entropy, b"view"));
        match src.fog_url {
            Some(ref url) => AccountKey::new_with_fog(
                &spend_private_key,
                &view_private_key,
                url.clone(),
                TEST_FOG_REPORT_KEY.to_string(),
                TEST_FOG_AUTHORITY_FINGERPRINT,
            ),
            None => AccountKey::new(&spend_private_key, &view_private_key),
        }
    }
}

// Helper function for using hkdf to derive a key
#[inline]
fn root_identity_hkdf_helper(ikm: &[u8; 32], info: &[u8]) -> Scalar {
    let mut result = [0u8; 32];
    let (_, hk) = Hkdf::<Blake2b256>::extract(None, &ikm[..]);

    // expand cannot fail because 32 bytes is a valid keylength for sha3/256
    hk.expand(info, &mut result).unwrap();

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
            "../../../test-data/transaction/identity/acct_priv_keys_from_root_entropy.yaml"
        ))
        .unwrap();

        for test in yaml[0].clone() {
            let root_entropy = yaml_as_byte_array(&test["root_entropy"]);
            let view_private_key = yaml_as_byte_array(&test["view_private_key"]);
            let spend_private_key = yaml_as_byte_array(&test["spend_private_key"]);

            let account_key = AccountKey::from(&RootIdentity {
                root_entropy: root_entropy.as_slice().try_into().unwrap(),
                fog_url: None,
            });
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
