// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Object representing a destination for change from a transaction

use mc_account_keys::{AccountKey, PublicAddress};

/// This is an API type for the transaction builder that helps name and organize
/// data that is passed when creating a change output.
///
/// When creating a standard change output, the primary address is used to
/// create the fog hint, and the change subaddress actually owns the change
/// output.
///
/// This object can be created from an AccountKey, but it could also be created
/// offline and then serialized and sent to a different machine.
#[derive(Clone, Debug)]
pub struct ChangeDestination {
    /// This is normally the default subaddress of an account. It is used to
    /// create the fog hint for the change output.
    pub primary_address: PublicAddress,
    /// This is a secret subaddress not known except by the owner of the
    /// account. It is the account to which all change outputs are actually
    /// sent. The account owner is able to confirm that an output is change
    /// by checking that it matches to the change subaddress.
    /// This should always be the change_subaddress for some AccountKey.
    pub change_subaddress: PublicAddress,
}

impl From<&AccountKey> for ChangeDestination {
    fn from(src: &AccountKey) -> Self {
        Self {
            primary_address: src.default_subaddress(),
            change_subaddress: src.change_subaddress(),
        }
    }
}

impl ChangeDestination {
    /// Send change to a particular subaddress of the account (perhaps not the
    /// change subaddress) This is useful in some things like mobilecoind
    pub fn from_subaddress_index(acct: &AccountKey, subaddress_index: u64) -> Self {
        Self {
            primary_address: acct.default_subaddress(),
            change_subaddress: acct.subaddress(subaddress_index),
        }
    }
}
