// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Object for 0x0100 Authenticated Sender memo type
//!
//! This was proposed for standardization in mobilecoinfoundation/mcips/pull/4

use super::{
    authenticated_common::{compute_category1_hmac, validate_authenticated_sender},
    credential::SenderMemoCredential,
    RegisteredMemoType,
};
use crate::impl_memo_type_conversions;
use core::convert::TryInto;
use mc_account_keys::{PublicAddress, ShortAddressHash};
use mc_crypto_keys::{
    CompressedRistrettoPublic, KexReusablePrivate, RistrettoPrivate, RistrettoPublic,
};
use subtle::Choice;

/// A memo that the sender writes to convey their identity in an authenticated
/// but deniable way, for the recipient of a TxOut.
///
/// See MCIP document for a discussion of the deniability property.
///
/// The recipient of this memo type should:
/// * First, use sender_address_hash to look up the address of the sender, from
///   among their contacts. If the sender isn't known then we can't validate.
/// * Then, call validate to check the mac and confirm authenticity.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthenticatedSenderMemo {
    /// The memo data
    memo_data: [u8; 44],
}

impl RegisteredMemoType for AuthenticatedSenderMemo {
    const MEMO_TYPE_BYTES: [u8; 2] = [0x01, 0x00];
}

impl AuthenticatedSenderMemo {
    /// Create a new AuthenticatedSenderMemo given credential, recipient public
    /// key, and tx out public key
    ///
    /// # Arguments:
    /// * cred: A sender memo credential tied to the address we wish to identify
    ///   ourselves as
    /// * receiving_subaddress_view_public_key: This is the view public key from
    ///   the public address of recipient
    /// * tx_out_public_key: The public_key of the TxOut to which we will attach
    ///   this memo
    pub fn new(
        cred: &SenderMemoCredential,
        receiving_subaddress_view_public_key: &RistrettoPublic,
        tx_out_public_key: &CompressedRistrettoPublic,
    ) -> Self {
        // The layout of the memo is:
        // [0-16] address hash
        // [16-28] unused
        // [28-44] HMAC

        let mut memo_data = [0u8; 44];
        memo_data[..16].copy_from_slice(cred.address_hash.as_ref());

        let shared_secret = cred
            .subaddress_spend_private_key
            .key_exchange(receiving_subaddress_view_public_key);

        let hmac_value = compute_category1_hmac(
            shared_secret.as_ref(),
            tx_out_public_key,
            Self::MEMO_TYPE_BYTES,
            &memo_data,
        );
        memo_data[28..].copy_from_slice(&hmac_value);

        Self { memo_data }
    }

    /// Get the sender address hash from the memo
    pub fn sender_address_hash(&self) -> ShortAddressHash {
        let bytes: [u8; 16] = self.memo_data[0..16].try_into().unwrap();
        ShortAddressHash::from(bytes)
    }

    /// Validate an AuthenticatedSenderMemo
    ///
    /// First, the client should look up the sender's Public Address from their
    /// hash. If it isn't a known contact we won't be able to authenticate
    /// them.
    ///
    /// Then they need to get the view private key corresponding to the
    /// subaddress that this TxOut was sent to. This is usually our default
    /// subaddress view private key.
    ///
    /// Finally we can validate the memo against these data. The
    /// tx_out_public_key is also under the mac, which prevents replay
    /// attacks.
    ///
    /// Arguments:
    /// * sender_address: The public address of the sender. This can be looked
    ///   up by the ShortAddressHash provided.
    /// * receiving_subaddress_view_private_key: This is usually our
    ///   default_subaddress_view_private_key, but should correspond to whatever
    ///   subaddress recieved this TxOut.
    /// * tx_out_public_key: The public key of the TxOut to which this memo is
    ///   attached.
    ///
    /// Returns:
    /// * subtle::Choice(1u8) if validation passed, subtle::Choice(0u8) if hmac
    ///   comparison failed.
    ///
    /// This function is constant-time.
    pub fn validate(
        &self,
        sender_address: &PublicAddress,
        receiving_subaddress_view_private_key: &RistrettoPrivate,
        tx_out_public_key: &CompressedRistrettoPublic,
    ) -> Choice {
        validate_authenticated_sender(
            sender_address,
            receiving_subaddress_view_private_key,
            tx_out_public_key,
            Self::MEMO_TYPE_BYTES,
            &self.memo_data,
        )
    }
}

impl From<&[u8; 44]> for AuthenticatedSenderMemo {
    fn from(src: &[u8; 44]) -> Self {
        let mut memo_data = [0u8; 44];
        memo_data.copy_from_slice(src);
        Self { memo_data }
    }
}

impl From<AuthenticatedSenderMemo> for [u8; 44] {
    fn from(src: AuthenticatedSenderMemo) -> [u8; 44] {
        src.memo_data
    }
}

impl_memo_type_conversions! { AuthenticatedSenderMemo }
