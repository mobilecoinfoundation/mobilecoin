// Copyright (c) 2018-2020 MobileCoin Inc.

//! CryptoNote-style View Key.
//!
//! A view key (a,B) contains half of a user's private information, and is used to identify
//! transaction outputs sent to the user, and to view the amounts of those outputs.

use core::hash::{Hash, Hasher};
use keys::{RistrettoPrivate, RistrettoPublic};
use serde::{Deserialize, Serialize};

/// The user's (a,B) keys.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ViewKey {
    /// The user's private key `a`.
    pub view_private_key: RistrettoPrivate,
    /// The user's public key `B`
    pub spend_public_key: RistrettoPublic,
}

impl ViewKey {
    /// A CryptoNote-style view key.
    ///
    /// # Arguments
    /// * `view_private_key` - The user's private view key `a`.
    /// * `spend_public_key` - The user's public spend key `B`.
    pub fn new(view_private_key: RistrettoPrivate, spend_public_key: RistrettoPublic) -> Self {
        ViewKey {
            view_private_key,
            spend_public_key,
        }
    }
}

impl Hash for ViewKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let view_public_key = RistrettoPublic::from(&self.view_private_key);
        view_public_key.hash(state);
        self.spend_public_key.hash(state);
    }
}

impl Eq for ViewKey {}

impl PartialEq for ViewKey {
    fn eq(&self, other: &Self) -> bool {
        RistrettoPublic::from(&self.view_private_key)
            .eq(&RistrettoPublic::from(&other.view_private_key))
            && self.spend_public_key.eq(&other.spend_public_key)
    }
}
