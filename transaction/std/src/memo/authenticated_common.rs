// Copyright (c) 2018-2021 The MobileCoin Foundation

//! HMAC code shared by all category 0x01 memos.

use hmac::{Hmac, Mac, NewMac};
use mc_crypto_keys::CompressedRistrettoPublic;
use sha2::Sha512;

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
    memo_data: &[u8],
) -> [u8; 16] {
    let mut mac = HmacSha512::new_from_slice(shared_secret.as_ref())
        .expect("hmac can take a key of any size");
    mac.update(tx_out_public_key.as_ref());
    mac.update(&memo_data[..(memo_data.len() - 16)]);
    let mut result = [0u8; 16];
    result.copy_from_slice(&mac.finalize().into_bytes()[0..16]);
    result
}
