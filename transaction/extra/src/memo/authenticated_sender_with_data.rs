// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Object for 0x0103 Authenticated Sender With Data memo type
//!
//! This was proposed for standardization in mobilecoinfoundation/mcips/pull/60

use super::{
    authenticated_common::{compute_authenticated_sender_memo, validate_authenticated_sender},
    credential::SenderMemoCredential,
    RegisteredMemoType,
};
use crate::impl_memo_type_conversions;
use mc_account_keys::{PublicAddress, ShortAddressHash};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
use subtle::Choice;

/// A memo that the sender writes to convey their identity in an authenticated
/// but deniable way, for the recipient of a TxOut, which also includes data
///
/// See mobilecoinfoundation/mcips/pull/4 for a discussion of the deniability
/// property.
///
/// The recipient of this memo type should:
/// * First, use sender_address_hash to look up the address of the sender, from
///   among their contacts. If the sender isn't known then we can't validate.
/// * Then, call validate to check the mac and confirm authenticity.
/// * We can extract the data for use with other applications like moby.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthenticatedSenderWithDataMemo {
    /// The memo data
    memo_data: [u8; 64],
}

impl RegisteredMemoType for AuthenticatedSenderWithDataMemo {
    const MEMO_TYPE_BYTES: [u8; 2] = [0x01, 0x03];
}

impl AuthenticatedSenderWithDataMemo {
    /// Create a new AuthenticatedSenderMemo given credential, recipient public
    /// key, and tx out public key and data
    ///
    /// # Arguments:
    /// * cred: A sender memo credential tied to the address we wish to identify
    ///   ourselves as
    /// * receiving_subaddress_view_public_key: This is the view public key from
    ///   the public address of recipient
    /// * tx_out_public_key: The public_key of the TxOut to which we will attach
    ///   this memo
    /// * data: The data
    pub fn new(
        cred: &SenderMemoCredential,
        receiving_subaddress_view_public_key: &RistrettoPublic,
        tx_out_public_key: &CompressedRistrettoPublic,
        data: &[u8],
    ) -> Self {
        // The layout of the memo is:
        // [0-16) address hash
        // [16-48) data
        // [48-64) HMAC
        let memo_data = compute_authenticated_sender_memo(
            Self::MEMO_TYPE_BYTES,
            cred,
            receiving_subaddress_view_public_key,
            tx_out_public_key,
            data,
        );
        Self { memo_data }
    }

    /// Get the sender address hash from the memo
    pub fn sender_address_hash(&self) -> ShortAddressHash {
        let bytes: [u8; 16] = self.memo_data[0..16].try_into().unwrap();
        ShortAddressHash::from(bytes)
    }

    /// Get the data from the memo
    pub fn data(&self) -> &[u8] {
        self.memo_data[16..48].try_into().unwrap()
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
    ///   subaddress received this TxOut.
    /// * tx_out_public_key: The public key of the TxOut to which this memo is
    ///   attached.
    ///
    /// Returns:
    /// * subtle::Choice(1u8) if validation passed, subtle::Choice(0u8) if HMAC
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

impl From<&[u8; 64]> for AuthenticatedSenderWithDataMemo {
    fn from(src: &[u8; 64]) -> Self {
        let mut memo_data = [0u8; 64];
        memo_data.copy_from_slice(src);
        Self { memo_data }
    }
}

impl From<AuthenticatedSenderWithDataMemo> for [u8; 64] {
    fn from(src: AuthenticatedSenderWithDataMemo) -> [u8; 64] {
        src.memo_data
    }
}

impl_memo_type_conversions! { AuthenticatedSenderWithDataMemo }
