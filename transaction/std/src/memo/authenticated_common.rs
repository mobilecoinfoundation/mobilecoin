// Copyright (c) 2018-2022 The MobileCoin Foundation

//! HMAC code shared by all category 0x01 memos.
//!
//! This validation scheme was proposed for standardization in
//! mobilecoinfoundation/mcips/pull/4

use mc_account_keys::{PublicAddress, ShortAddressHash};
use mc_crypto_keys::{CompressedRistrettoPublic, KexReusablePrivate, RistrettoPrivate};
use mc_crypto_memo_mac::compute_category1_hmac;
use subtle::{Choice, ConstantTimeEq};

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

    let expected_hmac = compute_category1_hmac(
        shared_secret.as_ref(),
        tx_out_public_key,
        memo_type_bytes,
        memo_data[..48].try_into().unwrap(),
    );
    let found_hmac: [u8; 16] = memo_data[(64 - 16)..].try_into().unwrap();
    result &= expected_hmac.ct_eq(&found_hmac);
    result
}
