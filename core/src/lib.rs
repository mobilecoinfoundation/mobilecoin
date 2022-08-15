//! Mobilecoin core types / functions

#![no_std]
#![warn(missing_docs)]
#![deny(unsafe_code)]
#![allow(non_snake_case)]

use curve25519_dalek::{scalar::Scalar};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroize;

use mc_crypto_hashes::{Blake2b512, Digest};
use mc_crypto_keys::{RistrettoPrivate};


pub mod consts;
use consts::*;

mod keys;
pub use keys::*;


/// Mobilecoin basic account object.
/// 
/// Typiclly derived via slip10, and containing root view and spend private keys.
#[derive(Zeroize)]
pub struct Account {
    /// Root view private key
    // TODO: can we make this non-public?
    pub view_private: ViewPrivate,
    /// Root spend private key
    // TODO: can we make this non-public?
    pub spend_private: SpendPrivate,
}

impl Account {

    /// Fetch the BIP39 path for a given account index
    pub const fn wallet_path(account_index: u32) -> [u32; 3] {
        [
            0x80000000 | USAGE_BIP44,
            0x80000000 | COINTYPE_MOBILECOIN,
            0x80000000 | (account_index & !0x80000000),
        ]
    }

    /// Create an account from existing private keys
    pub fn new(view_private: ViewPrivate, spend_private: SpendPrivate) -> Self {
        Self { view_private, spend_private }
    }

    /// Derive account keys from slip10 derived Ed25519 private key (see [`wallet_path`] for the BIP32 derivation path)
    pub fn slip10_derive(src: &[u8; 32]) -> Self {
        let mut okm = [0u8; 64];

        let view_kdf = Hkdf::<Sha512>::new(Some(b"mobilecoin-ristretto255-view"), src.as_ref());
        view_kdf
            .expand(b"", &mut okm)
            .expect("Invalid okm length when creating private view key");
        let view_scalar = Scalar::from_bytes_mod_order_wide(&okm);
        let view_private_key = RistrettoPrivate::from(view_scalar);

        let spend_kdf = Hkdf::<Sha512>::new(Some(b"mobilecoin-ristretto255-spend"), src.as_ref());
        spend_kdf
            .expand(b"", &mut okm)
            .expect("Invalid okm length when creating private spend key");
        let spend_scalar = Scalar::from_bytes_mod_order_wide(&okm);
        let spend_private_key = RistrettoPrivate::from(spend_scalar);

        Self{
            spend_private: SpendPrivate::from(spend_private_key), 
            view_private: ViewPrivate::from(view_private_key),
        }
    }

    /// Fetch keys for the i^th subaddress
    pub fn subaddress(&self, index: u64) -> Subaddress {
        let view_private = self.subaddress_view_private(index);
        let spend_private = self.subaddress_spend_private(index);

        Subaddress{view_private, spend_private}
    }

    /// Fetch keys for the default subaddress
    pub fn default_subaddress(&self) -> Subaddress {
        self.subaddress(DEFAULT_SUBADDRESS_INDEX)
    }

    /// The private view key for the i^th subaddress.
    fn subaddress_view_private(&self, index: u64) -> ViewPrivate {
        let a: &Scalar = self.view_private.as_ref().as_ref();

        // `Hs(a || n)`
        let Hs: Scalar = {
            let n = Scalar::from(index);
            let mut digest = Blake2b512::new();
            digest.update(SUBADDRESS_DOMAIN_TAG);
            digest.update(a.as_bytes());
            digest.update(n.as_bytes());
            Scalar::from_hash(digest)
        };

        let b: &Scalar = self.spend_private.as_ref().as_ref();
        let c = a * (Hs + b);
        ViewPrivate::from(RistrettoPrivate::from(c))
    }

    /// The private spend key for the i^th subaddress.
    fn subaddress_spend_private(&self, index: u64) -> SpendPrivate {
        let a: &Scalar = self.view_private.as_ref().as_ref();

        // `Hs(a || n)`
        let Hs: Scalar = {
            let n = Scalar::from(index);
            let mut digest = Blake2b512::new();
            digest.update(SUBADDRESS_DOMAIN_TAG);
            digest.update(a.as_bytes());
            digest.update(n.as_bytes());
            Scalar::from_hash(digest)
        };

        let b: &Scalar = self.spend_private.as_ref().as_ref();
        SpendPrivate::from(RistrettoPrivate::from(Hs + b))
    }
}

/// Mobilecoin basic sub-address object
pub struct Subaddress {
    /// sub-address view private key
    pub view_private: ViewPrivate,
    /// sub-address spend private key
    pub spend_private: SpendPrivate,
}


impl Subaddress {
    /// Fetch view public address
    pub fn view_public(&self) -> ViewPublic {
        ViewPublic::from(&self.view_private)
    }

    /// Fetch spend public address
    pub fn spend_public(&self) -> SpendPublic {
        SpendPublic::from(&self.spend_private)
    }
}


/// Mobilecoin basic public address object
pub struct PublicAddress {
    /// Public address view public key
    pub view_public: ViewPublic,
    /// Public address spend public key
    pub spend_public: SpendPublic,
}

/// Create a [`PublicAddress`] object for a given subaddress
impl From<&Subaddress> for PublicAddress {
    fn from(addr: &Subaddress) -> Self {
        Self{ 
            view_public: addr.view_public(),
            spend_public: addr.spend_public(),
        }
    }
}

impl PublicAddress {

}


#[cfg(test)]
mod tests {

    use mc_util_test_vector::TestVector;
    use mc_util_test_with_data::test_with_data;
    use mc_test_vectors_definitions::account_keys::DefaultSubaddrKeysFromAcctPrivKeys;

    use super::*;
    
    #[test_with_data(DefaultSubaddrKeysFromAcctPrivKeys::from_jsonl("../test-vectors/vectors"))]
    fn default_subaddr_keys_from_acct_priv_keys(case: DefaultSubaddrKeysFromAcctPrivKeys) {
        let spend_private_key = SpendPrivate::try_from(&case.spend_private_key).unwrap();
        let view_private_key = ViewPrivate::try_from(&case.view_private_key).unwrap();

        let account = Account::new(view_private_key, spend_private_key);

        let subaddress = account.subaddress(DEFAULT_SUBADDRESS_INDEX);

        assert_eq!(
            subaddress.view_private.to_bytes(),
            case.subaddress_view_private_key
        );
        assert_eq!(
            subaddress.spend_private.to_bytes(),
            case.subaddress_spend_private_key
        );

        assert_eq!(
            subaddress.view_public().to_bytes(),
            case.subaddress_view_public_key
        );
        assert_eq!(
            subaddress.spend_public().to_bytes(),
            case.subaddress_spend_public_key
        );
    }

}
