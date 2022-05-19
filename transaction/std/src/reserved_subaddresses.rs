// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Object containing subaddresses of MobileCoin reserved subaddress indices

use mc_account_keys::{AccountKey, PublicAddress};

/// This is an API type for the transaction builder that helps name and organize
/// data that is passed when creating outputs for reserved subaddresses
///
/// When creating outputs, the primary address is used to create the fog hint,
/// but the special output types like change outputs and gift code outputs are
/// sent to reserved subaddresses. This object provides a way of tracking the
/// reserved subaddresses within the platform.
///
/// This object can be created from an AccountKey, but it can also be created
/// offline and then serialized and sent to a different machine.
#[derive(Clone, Debug)]
pub struct ReservedSubaddresses {
    /// This is normally the default subaddress of an account. It is used to
    /// create the fog hint for the change output.
    pub primary_address: PublicAddress,

    /// A secret reserved subaddress not known except by the owner of the
    /// account. It is the account to which all change outputs are actually
    /// sent. The account owner is able to confirm that an output is change
    /// by checking that it matches to the change subaddress.
    /// This should always be the change_subaddress for some AccountKey.
    pub change_subaddress: PublicAddress,

    /// A secret reserved subaddress to which gift code ouputs are sent
    /// when they are created. Similarly to the change_subaddress, gift code
    /// creators can check to see gift codes they've created by checking outputs
    /// at this subaddress
    pub gift_code_subaddress: PublicAddress,
}

impl From<&AccountKey> for ReservedSubaddresses {
    fn from(src: &AccountKey) -> Self {
        Self {
            primary_address: src.default_subaddress(),
            change_subaddress: src.change_subaddress(),
            gift_code_subaddress: src.gift_code_subaddress(),
        }
    }
}

impl ReservedSubaddresses {
    /// Set alternate subaddresseses for reserved addresses. This is useful in
    /// some things like mobilecoind
    pub fn from_subaddress_index(
        acct: &AccountKey,
        change_subaddress_index: Option<u64>,
        gift_code_subaddress_index: Option<u64>,
    ) -> Self {
        let change_subaddress = if let Some(change_subaddress) = change_subaddress_index {
            acct.subaddress(change_subaddress)
        } else {
            acct.change_subaddress()
        };

        let gift_code_subaddress = if let Some(gift_code_subaddress) = gift_code_subaddress_index {
            acct.subaddress(gift_code_subaddress)
        } else {
            acct.gift_code_subaddress()
        };

        Self {
            primary_address: acct.default_subaddress(),
            change_subaddress,
            gift_code_subaddress,
        }
    }
}
