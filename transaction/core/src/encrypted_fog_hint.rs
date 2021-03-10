// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Define DiscoveryHint buffer size, and serialization defs for it
//! Also define `fake_onetime_hint` which samples the distribution that
//! should be used for these hints when there is no discovery server.
//!
//! Note: Using generic array because rust has poor support for implementing
//! builtin traits on arrays of size > 32.

use alloc::{vec, vec::Vec};
use core::{convert::TryFrom, fmt};
use generic_array::{
    typenum::{Diff, Unsigned, U84},
    GenericArray,
};
use mc_crypto_box::{CryptoBox, VersionedCryptoBox};
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::Ristretto;
use mc_util_from_random::FromRandom;
use prost::{
    bytes::{Buf, BufMut},
    encoding::{bytes, skip_field, DecodeContext, WireType},
    DecodeError, Message,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

// The length of the encrypted fog hint field in the ledger.
// Must be at least as large as mc_crypto_box::VersionedCryptoBox::FooterSize.
// Footersize = 50, + 32 for one curve point, + 2 bytes of magic / padding space
// for future needs
pub type EncryptedFogHintSize = U84;
pub const ENCRYPTED_FOG_HINT_LEN: usize = EncryptedFogHintSize::USIZE;

type Bytes = GenericArray<u8, EncryptedFogHintSize>;

#[derive(
    Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize, Default, Digestible,
)]
#[digestible(transparent)]
pub struct EncryptedFogHint {
    bytes: Bytes,
}

// AsRef and AsMut slice conversions
impl AsRef<Bytes> for EncryptedFogHint {
    fn as_ref(&self) -> &Bytes {
        &self.bytes
    }
}

impl AsMut<Bytes> for EncryptedFogHint {
    fn as_mut(&mut self) -> &mut Bytes {
        &mut self.bytes
    }
}

impl From<Bytes> for EncryptedFogHint {
    fn from(bytes: Bytes) -> Self {
        Self { bytes }
    }
}

impl From<&[u8; ENCRYPTED_FOG_HINT_LEN]> for EncryptedFogHint {
    #[inline]
    fn from(a: &[u8; ENCRYPTED_FOG_HINT_LEN]) -> Self {
        Self {
            bytes: GenericArray::clone_from_slice(&a[..]),
        }
    }
}

impl<'bytes> TryFrom<&'bytes [u8]> for EncryptedFogHint {
    type Error = ();

    fn try_from(slice: &'bytes [u8]) -> Result<Self, ()> {
        if slice.len() == ENCRYPTED_FOG_HINT_LEN {
            Ok(Self {
                bytes: GenericArray::clone_from_slice(slice),
            })
        } else {
            Err(())
        }
    }
}

impl EncryptedFogHint {
    #[inline]
    pub fn new(a: &[u8; ENCRYPTED_FOG_HINT_LEN]) -> Self {
        Self {
            bytes: GenericArray::clone_from_slice(&a[..]),
        }
    }
    #[inline]
    pub fn to_bytes(&self) -> [u8; ENCRYPTED_FOG_HINT_LEN] {
        let mut result = [0u8; ENCRYPTED_FOG_HINT_LEN];
        result.copy_from_slice(self.as_ref());
        result
    }

    /// fake_onetime_hint
    /// To be used in prod when sending to a recipient with no known fog server
    /// This means it should be indistinguishable from an ecies encryption of a
    /// random plaintext. There are several ways we could sample that
    /// distribution but the simplest is to do exactly that. This is also
    /// future-proof if we later tweak the cryptobox implementation.
    pub fn fake_onetime_hint<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        // Make plaintext of the right size
        let plaintext = GenericArray::<
            u8,
            Diff<EncryptedFogHintSize, <VersionedCryptoBox as CryptoBox<Ristretto>>::FooterSize>,
        >::default();
        // Make a random key
        let key = mc_crypto_keys::RistrettoPublic::from_random(rng);
        // encrypt_in_place into the buffer
        let bytes = VersionedCryptoBox::default()
            .encrypt_fixed_length(rng, &key, &plaintext)
            .expect("Encryption error");
        Self { bytes }
    }
}

impl Message for EncryptedFogHint {
    fn encode_raw<B>(&self, buf: &mut B)
    where
        B: BufMut,
    {
        bytes::encode(1, &self.to_bytes().to_vec(), buf)
    }
    fn merge_field<B>(
        &mut self,
        tag: u32,
        wire_type: WireType,
        buf: &mut B,
        ctx: DecodeContext,
    ) -> Result<(), DecodeError>
    where
        B: Buf,
    {
        if tag == 1 {
            let mut vbuf = Vec::new();
            bytes::merge(wire_type, &mut vbuf, buf, ctx)?;
            if vbuf.len() != ENCRYPTED_FOG_HINT_LEN {
                return Err(DecodeError::new(alloc::format!(
                    "EncryptedFogHint: expected {} bytes, got {}",
                    ENCRYPTED_FOG_HINT_LEN,
                    vbuf.len()
                )));
            }
            let mut abuf: [u8; ENCRYPTED_FOG_HINT_LEN] = [0u8; ENCRYPTED_FOG_HINT_LEN];
            abuf.copy_from_slice(&vbuf[0..ENCRYPTED_FOG_HINT_LEN]);
            *self = Self::new(&abuf);
            Ok(())
        } else {
            skip_field(wire_type, tag, buf, ctx)
        }
    }
    fn encoded_len(&self) -> usize {
        bytes::encoded_len(1, &vec![0u8; ENCRYPTED_FOG_HINT_LEN])
    }
    fn clear(&mut self) {
        *self = Self::default();
    }
}

impl fmt::Debug for EncryptedFogHint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EncryptedFogHint({})", hex_fmt::HexFmt(self.as_ref()))
    }
}

#[cfg(test)]
mod testing {
    use super::*;

    #[test]
    fn test_fog_hint_serde() {
        let a = EncryptedFogHint::new(&[17u8; ENCRYPTED_FOG_HINT_LEN]);
        let a_ser = mc_util_serial::serialize(&a).unwrap();
        let b: EncryptedFogHint = mc_util_serial::deserialize(&a_ser).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }
}
