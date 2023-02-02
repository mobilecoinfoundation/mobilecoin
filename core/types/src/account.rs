// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin Account and Subaddress objects

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::keys::{
    RootSpendPrivate, RootSpendPublic, RootViewPrivate, RootViewPublic, SubaddressSpendPrivate,
    SubaddressSpendPublic, SubaddressViewPrivate, SubaddressViewPublic,
};

/// An object which represents a subaddress, and has RingCT-style
/// view and spend public keys.
pub trait RingCtAddress {
    /// Get the subaddress' view public key
    fn view_public_key(&self) -> SubaddressViewPublic;
    /// Get the subaddress' spend public key
    fn spend_public_key(&self) -> SubaddressSpendPublic;
}

impl<T: RingCtAddress> RingCtAddress for &T {
    fn view_public_key(&self) -> SubaddressViewPublic {
        T::view_public_key(self)
    }

    fn spend_public_key(&self) -> SubaddressSpendPublic {
        T::spend_public_key(self)
    }
}

/// MobileCoin basic account object.
///
/// Typically derived via slip10, and containing root view and spend private
/// keys.
#[derive(Debug, Zeroize)]
pub struct Account {
    /// Root view private key
    view_private: RootViewPrivate,
    /// Root spend private key
    spend_private: RootSpendPrivate,
}

impl Account {
    /// Create an account from existing private keys
    pub fn new(view_private: RootViewPrivate, spend_private: RootSpendPrivate) -> Self {
        Self {
            view_private,
            spend_private,
        }
    }

    /// Fetch account view public key
    pub fn view_public_key(&self) -> RootViewPublic {
        RootViewPublic::from(&self.view_private)
    }

    /// Fetch account spend public key
    pub fn spend_public_key(&self) -> RootSpendPublic {
        RootSpendPublic::from(&self.spend_private)
    }

    /// Fetch account view private key
    pub fn view_private_key(&self) -> &RootViewPrivate {
        &self.view_private
    }

    /// Fetch account spend private key
    pub fn spend_private_key(&self) -> &RootSpendPrivate {
        &self.spend_private
    }
}

/// MobileCoin view only account object.
///
/// Derived from an [Account] object, used where spend key custody is external
/// (offline or via hardware). Protobuf encoding is equivalent to
/// [mc_account_keys::ViewAccountKey]
#[derive(Zeroize)]
pub struct ViewAccount {
    /// Root view private key
    view_private: RootViewPrivate,

    /// Root spend public key
    spend_public: RootSpendPublic,
}

impl ViewAccount {
    /// Create an view-only account from existing private keys
    pub fn new(view_private: RootViewPrivate, spend_public: RootSpendPublic) -> Self {
        Self {
            view_private,
            spend_public,
        }
    }

    /// Fetch account view public key
    pub fn view_public_key(&self) -> RootViewPublic {
        RootViewPublic::from(&self.view_private)
    }

    /// Fetch account spend public key
    pub fn spend_public_key(&self) -> &RootSpendPublic {
        &self.spend_public
    }

    /// Fetch account view private key
    pub fn view_private_key(&self) -> &RootViewPrivate {
        &self.view_private
    }
}

impl From<&Account> for ViewAccount {
    fn from(a: &Account) -> Self {
        Self {
            view_private: a.view_private_key().clone(),
            spend_public: a.spend_public_key(),
        }
    }
}

/// MobileCoin spend subaddress object.
///
/// Contains view and spend private keys.
#[derive(Clone, Debug, PartialEq)]
pub struct SpendSubaddress {
    /// sub-address view private key
    pub view_private: SubaddressViewPrivate,
    /// sub-address spend private key
    pub spend_private: SubaddressSpendPrivate,
}

impl RingCtAddress for SpendSubaddress {
    /// Fetch view public address
    fn view_public_key(&self) -> SubaddressViewPublic {
        SubaddressViewPublic::from(&self.view_private)
    }

    /// Fetch spend public address
    fn spend_public_key(&self) -> SubaddressSpendPublic {
        SubaddressSpendPublic::from(&self.spend_private)
    }
}

impl SpendSubaddress {
    /// Fetch subaddress view private key
    pub fn view_private_key(&self) -> &SubaddressViewPrivate {
        &self.view_private
    }

    /// Fetch subaddress spend private key
    pub fn spend_private_key(&self) -> &SubaddressSpendPrivate {
        &self.spend_private
    }
}

/// MobileCoin view-only subaddress object.
///
/// Contains view private and spend public key.
#[derive(Clone, Debug, PartialEq)]
pub struct ViewSubaddress {
    /// sub-address view private key
    pub view_private: SubaddressViewPrivate,

    /// sub-address spend private key
    pub spend_public: SubaddressSpendPublic,
}

impl RingCtAddress for ViewSubaddress {
    /// Fetch view public address
    fn view_public_key(&self) -> SubaddressViewPublic {
        SubaddressViewPublic::from(&self.view_private)
    }

    /// Fetch spend public address
    fn spend_public_key(&self) -> SubaddressSpendPublic {
        self.spend_public.clone()
    }
}

impl ViewSubaddress {
    /// Fetch subaddress view private key
    pub fn view_private_key(&self) -> &SubaddressViewPrivate {
        &self.view_private
    }
}

/// MobileCoin public subaddress object
///
/// Contains view and spend public keys
#[derive(Clone, Debug, PartialEq)]
pub struct PublicSubaddress {
    /// Subaddress view public key
    pub view_public: SubaddressViewPublic,
    /// Subaddress spend public key
    pub spend_public: SubaddressSpendPublic,
}

impl RingCtAddress for PublicSubaddress {
    /// Fetch view public address
    fn view_public_key(&self) -> SubaddressViewPublic {
        self.view_public.clone()
    }

    /// Fetch spend public address
    fn spend_public_key(&self) -> SubaddressSpendPublic {
        self.spend_public.clone()
    }
}

/// Create a [`PublicSubaddress`] object from a [`SpendSubaddress`]
impl From<&SpendSubaddress> for PublicSubaddress {
    fn from(addr: &SpendSubaddress) -> Self {
        Self {
            view_public: addr.view_public_key(),
            spend_public: addr.spend_public_key(),
        }
    }
}

/// Create a [`PublicSubaddress`] object from a [`ViewSubaddress`]
impl From<&ViewSubaddress> for PublicSubaddress {
    fn from(addr: &ViewSubaddress) -> Self {
        Self {
            view_public: addr.view_public_key(),
            spend_public: addr.spend_public_key(),
        }
    }
}

/// Account ID object, derived from an [AccountKey] and used to identify
/// individual accounts.
#[derive(Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AccountId([u8; 32]);

/// Display [AccountId] as a hex encoded string
impl core::fmt::Display for AccountId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for v in self.0 {
            write!(f, "{:02X}", v)?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for AccountId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AccountId(")?;
        for v in self.0 {
            write!(f, "{:02X}", v)?;
        }
        write!(f, ")")
    }
}

/// Access raw [AccountId] hash
impl AsRef<[u8; 32]> for AccountId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Create [AccountId] object from raw hash
impl From<[u8; 32]> for AccountId {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// Create [AccountId] object from raw hash
impl From<&[u8; 32]> for AccountId {
    fn from(value: &[u8; 32]) -> Self {
        Self(*value)
    }
}

/// Represents a "standard" public address hash created using merlin,
/// used in memos as a compact representation of a MobileCoin public address.
/// This hash is collision resistant.
#[derive(Clone, Default, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct ShortAddressHash([u8; 16]);

impl From<[u8; 16]> for ShortAddressHash {
    fn from(src: [u8; 16]) -> Self {
        Self(src)
    }
}

impl From<ShortAddressHash> for [u8; 16] {
    fn from(src: ShortAddressHash) -> [u8; 16] {
        src.0
    }
}

impl AsRef<[u8; 16]> for ShortAddressHash {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl subtle::ConstantTimeEq for ShortAddressHash {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl core::fmt::Display for ShortAddressHash {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        for b in self.0 {
            write!(formatter, "{:02x}", b)?;
        }
        Ok(())
    }
}
