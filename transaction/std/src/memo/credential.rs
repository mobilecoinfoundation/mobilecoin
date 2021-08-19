// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_account_keys::{AccountKey, PublicAddress, ShortAddressHash};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};

/// A credential that a sender can use to make an Authenticated Sender Memo.
///
/// This can in principle correspond to any subaddress, but usually it
/// corresponds to the default subaddress. The function which creates this from
/// an AccountKey will use the default subaddress.
///
/// An example use-case where it might be helpful to use something other than
/// From<&AccountKey> here is if, an exchange is sending MOB to Bob, and
/// they would like to identify using the subaddress that he uses to deposit
/// MOB. This way a chat client like signal can associate the deposits and
/// withdrawals with the same chat interaction.
#[derive(Debug, Clone)]
pub struct SenderMemoCredential {
    /// The address hash of the public address that we wish to identify as
    pub address_hash: ShortAddressHash,
    /// The (subaddress) spend private key hash of the public address that we
    /// wish to identify as
    pub subaddress_spend_private_key: RistrettoPrivate,
}

impl SenderMemoCredential {
    /// Make a new SenderMemoCredential from a public address, and the spend
    /// private key corresponding to that subaddress
    pub fn new_from_address_and_spend_private_key(
        address: &PublicAddress,
        subaddress_spend_private_key: RistrettoPrivate,
    ) -> Self {
        debug_assert!(
            address.spend_public_key() == &RistrettoPublic::from(&subaddress_spend_private_key),
            "provided sender private key didn't match sender public address!"
        );
        let address_hash = ShortAddressHash::from(address);
        Self {
            address_hash,
            subaddress_spend_private_key,
        }
    }
}

impl From<&AccountKey> for SenderMemoCredential {
    fn from(src: &AccountKey) -> Self {
        Self::new_from_address_and_spend_private_key(
            &src.default_subaddress(),
            src.default_subaddress_spend_private(),
        )
    }
}
