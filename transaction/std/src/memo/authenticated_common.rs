// Copyright (c) 2018-2021 The MobileCoin Foundation

//! HMAC code shared by all category 0x01 memos.
//!
//! This validation scheme was proposed for standardization in
//! mobilecoinfoundation/mcips/pull/4

use hmac::{Hmac, Mac, NewMac};
use mc_account_keys::{PublicAddress, ShortAddressHash};
use mc_crypto_keys::{CompressedRistrettoPublic, KexReusablePrivate, RistrettoPrivate};
use sha2::Sha512;
use std::convert::TryInto;
use subtle::{Choice, ConstantTimeEq};

type HmacSha512 = Hmac<Sha512>;

/// Shared code for memo types in category 0x01, whose last 16 bytes is an HMAC
/// This HMAC key is always first the 32 bytes of a shared secret, then the 32
/// bytes of the TxOut public key, then all the bytes of the decrypted memo,
/// omitting the last 16 which are the HMAC.
///
/// Arguments:
/// * shared_secret, produced in some way between sender and recipient.
/// * tx_out_public_key, from the TxOut associated to this memo
/// * memo_data. The last 16 bytes of this slice will be ignored.
pub fn compute_category1_hmac(
    shared_secret: &[u8; 32],
    tx_out_public_key: &CompressedRistrettoPublic,
    memo_type_bytes: [u8; 2],
    memo_data: &[u8; 44],
) -> [u8; 16] {
    let mut mac = HmacSha512::new_from_slice(shared_secret.as_ref())
        .expect("hmac can take a key of any size");
    // First add domain separation
    mac.update(b"mc-memo-mac");
    // Next add tx_out_public_key, binding this mac to a paritcular TxOut
    mac.update(tx_out_public_key.as_ref());
    // Next add memo type bytes (2)
    mac.update(&memo_type_bytes);
    // Next add all the memo data bytes, except for the last 16 (which are the mac)
    mac.update(&memo_data[..(44 - 16)]);
    let mut result = [0u8; 16];
    result.copy_from_slice(&mac.finalize().into_bytes()[0..16]);
    result
}

/// Shared code for validation of 0x0100 and 0x0101 memos
pub fn validate_authenticated_sender(
    sender_address: &PublicAddress,
    receiving_subaddress_view_private_key: &RistrettoPrivate,
    tx_out_public_key: &CompressedRistrettoPublic,
    memo_type_bytes: [u8; 2],
    memo_data: &[u8; 44],
) -> Choice {
    let mut result = Choice::from(1u8);
    let expected_sender_address_hash = ShortAddressHash::from(sender_address);
    let hash_bytes: [u8; 16] = memo_data[0..16].try_into().expect("length mismatch");
    let found_sender_address_hash = ShortAddressHash::from(hash_bytes);
    result &= expected_sender_address_hash.ct_eq(&found_sender_address_hash);

    let shared_secret =
        receiving_subaddress_view_private_key.key_exchange(sender_address.spend_public_key());

    let expected_hmac = compute_category1_hmac(
        shared_secret.as_ref(),
        tx_out_public_key,
        memo_type_bytes,
        memo_data,
    );
    let found_hmac: [u8; 16] = memo_data[28..].try_into().unwrap();
    result &= expected_hmac.ct_eq(&found_hmac);
    result
}
