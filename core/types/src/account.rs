// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin Account and Subaddress objects

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
