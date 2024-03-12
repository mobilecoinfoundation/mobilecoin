// Copyright (c) 2018-2023 The MobileCoin Foundation

//! HMAC code shared by all category 0x01 memos.
//!
//! This validation scheme was proposed for standardization in
//! mobilecoinfoundation/mcips/pull/4

use mc_account_keys::{PublicAddress, ShortAddressHash};
use mc_crypto_keys::{
    CompressedRistrettoPublic, KexReusablePrivate, RistrettoPrivate, RistrettoPublic,
};
use subtle::{Choice, ConstantTimeEq};

use crate::SenderMemoCredential;

/// Shared code for validation of 0x0100 and 0x0101 memos
pub fn validate_authenticated_sender(
    sender_address: &PublicAddress,
    receiving_subaddress_view_private_key: &RistrettoPrivate,
    tx_out_public_key: &CompressedRistrettoPublic,
    memo_type_bytes: [u8; 2],
    memo_data: &[u8; 64],
) -> Choice {
    let mut result = Choice::from(1u8);
    let expected_sender_address_hash = ShortAddressHash::from(sender_address);
    let hash_bytes: [u8; 16] = memo_data[0..16].try_into().expect("length mismatch");
    let found_sender_address_hash = ShortAddressHash::from(hash_bytes);
    result &= expected_sender_address_hash.ct_eq(&found_sender_address_hash);

    let shared_secret =
        receiving_subaddress_view_private_key.key_exchange(sender_address.spend_public_key());

    let expected_hmac = mc_crypto_memo_mac::compute_category1_hmac(
        shared_secret.as_ref(),
        tx_out_public_key,
        memo_type_bytes,
        &memo_data[..48].try_into().expect("length mismatch"),
    );
    let found_hmac: [u8; 16] = memo_data[(64 - 16)..].try_into().expect("length mismatch");
    result &= expected_hmac.ct_eq(&found_hmac);
    result
}

/// Shared code for creation of an authenticated sender memo with additional
/// data
pub fn compute_authenticated_sender_memo(
    memo_type_bytes: [u8; 2],
    cred: &SenderMemoCredential,
    receiving_subaddress_view_public_key: &RistrettoPublic,
    tx_out_public_key: &CompressedRistrettoPublic,
    data: &[u8],
) -> [u8; 64] {
    let mut memo_data = [0u8; 64];
    memo_data[..16].copy_from_slice(cred.address_hash.as_ref());
    memo_data[16..48].copy_from_slice(data);

    let shared_secret = cred
        .subaddress_spend_private_key
        .key_exchange(receiving_subaddress_view_public_key);

    let hmac_value = mc_crypto_memo_mac::compute_category1_hmac(
        shared_secret.as_ref(),
        tx_out_public_key,
        memo_type_bytes,
        &memo_data[..48].try_into().expect("length mismatch"),
    );
    memo_data[48..].copy_from_slice(&hmac_value);
    memo_data
}
