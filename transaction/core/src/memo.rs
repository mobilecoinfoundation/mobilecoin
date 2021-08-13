// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Definition of memo payload type
//!
//! This memo payload and its encryption scheme was proposed for standardization
//! in mobilecoinfoundation/mcips/pull/3.
//!
//! The encrypted memo of TxOut's is designed to have one encryption scheme and
//! the payload is an extensible format. Two bytes are used for a schema type,
//! and fourty four bytes are used for data according to that schema.
//!
//! The encryption details are defined in the transaction crate, but we would
//! like to avoid making the introduction of a new schema require changes to
//! the transaction-core crate, because this would require a new consensus
//! enclave.
//!
//! We also would like to avoid implementing the interpretation of memo data
//! in the transaction crate, for much the same reasons.
//!
//! Therefore, the code is organized as follows:
//! - A MemoPayload is the collection of bytes ready to be encrypted. This can
//!   be used to construct a TxOut, and it is encrypted at that time. This is
//!   defined in transaction-core crate.
//! - The memo module in transaction-std crate defines specific structures that
//!   can be converted to a MemoPayload, and provides a function that can
//!   interpret a MemoPayload as one of the known high-level objects.
//! - The TransactionBuilder now uses a memo builder to set the "policy" around
//!   memos for this transaction, so that low-level handling of memos is not
//!   needed by the user of the TransactionBuilder.
//! - When interpretting memos on TxOut's that you recieved, the memo module
//!   functionality can be used to assist.

use aes::{
    cipher::{FromBlockCipher, StreamCipher},
    Aes256, Aes256Ctr, NewBlockCipher,
};
use core::convert::{TryFrom, TryInto};
use displaydoc::Display;
use generic_array::{
    sequence::Split,
    typenum::{U32, U46, U48},
    GenericArray,
};
use hkdf::Hkdf;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_util_repr_bytes::{
    derive_into_vec_from_repr_bytes, derive_prost_message_from_repr_bytes,
    derive_repr_bytes_from_as_ref_and_try_from, derive_serde_from_repr_bytes,
};
use sha2::Sha512;

/// An encrypted memo, which can be decrypted by the recipient of a TxOut.
#[derive(Clone, Copy, Default, Debug, Eq, Hash, Digestible, Ord, PartialEq, PartialOrd)]
pub struct EncryptedMemo(GenericArray<u8, U46>);

impl AsRef<[u8]> for EncryptedMemo {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<GenericArray<u8, U46>> for EncryptedMemo {
    fn as_ref(&self) -> &GenericArray<u8, U46> {
        &self.0
    }
}

impl From<EncryptedMemo> for GenericArray<u8, U46> {
    fn from(src: EncryptedMemo) -> Self {
        src.0
    }
}

impl From<GenericArray<u8, U46>> for EncryptedMemo {
    fn from(src: GenericArray<u8, U46>) -> Self {
        Self(src)
    }
}

impl TryFrom<&[u8]> for EncryptedMemo {
    type Error = MemoError;
    fn try_from(src: &[u8]) -> Result<EncryptedMemo, Self::Error> {
        if src.len() == 46 {
            Ok(Self(*GenericArray::from_slice(src)))
        } else {
            Err(MemoError::BadLength(src.len()))
        }
    }
}

derive_repr_bytes_from_as_ref_and_try_from!(EncryptedMemo, U46);
derive_into_vec_from_repr_bytes!(EncryptedMemo);
derive_serde_from_repr_bytes!(EncryptedMemo);
derive_prost_message_from_repr_bytes!(EncryptedMemo);

impl EncryptedMemo {
    /// Helper to ease syntax when decrypting
    ///
    /// The shared-secret is expected to be the TxOut shared secret of the TxOut
    /// that this memo is associated to.
    pub fn decrypt(&self, shared_secret: &RistrettoPublic) -> MemoPayload {
        MemoPayload::decrypt_from(self, shared_secret)
    }
}

/// A plaintext memo payload, with accessors to easily access the memo type
/// bytes and memo data bytes. High-level memo objects should be convertible
/// to MemoPayload. Deserialization, across all high-level memo types, is
/// done in mc-transaction-std crate.
///
/// Note that a memo payload may be invalid / uninterpretable, or refer to new
/// memo types that have been introduced at a later date.
#[derive(Clone, Copy, Default, Debug, Eq, Digestible, Ord, PartialEq, PartialOrd)]
pub struct MemoPayload(GenericArray<u8, U46>);

impl MemoPayload {
    /// Create a new memo payload from given type bytes and data bytes
    pub fn new(memo_type: [u8; 2], memo_data: [u8; 44]) -> Self {
        let mut result = Self::default();
        result.0[0..2].copy_from_slice(&memo_type);
        result.0[2..46].copy_from_slice(&memo_data);
        result
    }

    /// Get the memo type bytes (two bytes)
    pub fn get_memo_type(&self) -> &[u8; 2] {
        self.0.as_slice()[0..2].try_into().expect("length mismatch")
    }

    /// Get the memo data bytes (fourty-four bytes)
    pub fn get_memo_data(&self) -> &[u8; 44] {
        self.0.as_slice()[2..46]
            .try_into()
            .expect("length mismatch")
    }

    /// Encrypt this memo payload using a given shared-secret, consuming it and
    /// returning underlying buffer.
    ///
    /// The shared-secret is expected to be the TxOut shared secret of the TxOut
    /// that this memo is associated to.
    pub fn encrypt(mut self, shared_secret: &RistrettoPublic) -> EncryptedMemo {
        self.apply_keystream(&shared_secret);
        EncryptedMemo(self.0)
    }

    /// Decrypt an EncryptedMemoPayload using a given shared secret, consuming
    /// it and returning the underlying buffer.
    pub fn decrypt_from(encrypted: &EncryptedMemo, shared_secret: &RistrettoPublic) -> Self {
        let mut result = Self::from(encrypted.0);
        result.apply_keystream(&shared_secret);
        result
    }

    // Apply AES256 keystream to internal buffer.
    // This is not a user-facing API, since from the user's point of view this
    // object always represents decrypted bytes.
    //
    // The argument is supposed to be the TxOut shared secret associated to the
    // memo.
    fn apply_keystream(&mut self, shared_secret: &RistrettoPublic) {
        // Use HKDF-SHA512 to produce an AES key and AES nonce
        let shared_secret = CompressedRistrettoPublic::from(shared_secret);
        let kdf = Hkdf::<Sha512>::new(Some(b"mc-memo-okm"), shared_secret.as_ref());
        // OKM is "output key material", see RFC HKDF for discussion of terms
        let mut okm = GenericArray::<u8, U48>::default();
        kdf.expand(b"", okm.as_mut_slice())
            .expect("Digest output size is insufficient");

        let (key, nonce) = Split::<u8, U32>::split(okm);

        // Apply AES-256 in counter mode to the buffer
        let mut aes256ctr = Aes256Ctr::from_block_cipher(Aes256::new(&key), &nonce);
        aes256ctr.apply_keystream(self.0.as_mut_slice());
    }
}

impl AsRef<[u8]> for MemoPayload {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<GenericArray<u8, U46>> for MemoPayload {
    fn as_ref(&self) -> &GenericArray<u8, U46> {
        &self.0
    }
}

impl From<MemoPayload> for GenericArray<u8, U46> {
    fn from(src: MemoPayload) -> Self {
        src.0
    }
}

impl From<GenericArray<u8, U46>> for MemoPayload {
    fn from(src: GenericArray<u8, U46>) -> Self {
        Self(src)
    }
}

impl TryFrom<&[u8]> for MemoPayload {
    type Error = MemoError;
    fn try_from(src: &[u8]) -> Result<MemoPayload, Self::Error> {
        if src.len() == 46 {
            Ok(Self(*GenericArray::from_slice(src)))
        } else {
            Err(MemoError::BadLength(src.len()))
        }
    }
}

derive_repr_bytes_from_as_ref_and_try_from!(MemoPayload, U46);
derive_into_vec_from_repr_bytes!(MemoPayload);
derive_serde_from_repr_bytes!(MemoPayload);
derive_prost_message_from_repr_bytes!(MemoPayload);

#[derive(Display, Debug)]
pub enum MemoError {
    /// Wrong length for memo payload: {0}
    BadLength(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    #[test]
    fn test_memo_payload_round_trip() {
        let mut rng = Hc128Rng::seed_from_u64(37);

        let key1 = RistrettoPublic::from_random(&mut rng);
        let key2 = RistrettoPublic::from_random(&mut rng);

        let memo1 = MemoPayload::default();
        let e_memo1 = memo1.clone().encrypt(&key1);
        assert_eq!(memo1, e_memo1.decrypt(&key1), "roundtrip failed");

        let memo2 = MemoPayload::new([1u8, 2u8], [47u8; 44]);
        let e_memo2 = memo2.clone().encrypt(&key1);
        assert_eq!(memo2, e_memo2.decrypt(&key1), "roundtrip failed");

        let memo1 = MemoPayload::default();
        let e_memo1 = memo1.clone().encrypt(&key1);
        assert_ne!(
            memo1,
            e_memo1.decrypt(&key2),
            "decrypting with wrong key succeeded"
        );

        let memo2 = MemoPayload::new([1u8, 2u8], [47u8; 44]);
        let e_memo2 = memo2.clone().encrypt(&key2);
        assert_ne!(
            memo2,
            e_memo2.decrypt(&key1),
            "decrypting with wrong key succeeded"
        );
    }
}
