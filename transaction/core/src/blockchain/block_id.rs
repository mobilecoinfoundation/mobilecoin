// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::ConvertError;
use alloc::{vec, vec::Vec};
use core::{
    convert::TryFrom,
    fmt::Debug,
    hash::{Hash, Hasher},
};
use generic_array::{typenum::Unsigned, GenericArray};
use mc_crypto_digestible::{Digest, Digestible};
use mc_crypto_hashes::Blake2b256;
use prost::{
    bytes::{Buf, BufMut},
    encoding::{bytes, skip_field, DecodeContext, WireType},
    DecodeError, Message,
};
use serde::{Deserialize, Serialize};

#[repr(transparent)]
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
/// Identifies a block with its hash.
pub struct BlockID<D: Digest = Blake2b256>(pub GenericArray<u8, D::OutputSize>);

impl<D: Digest> Digestible for BlockID<D> {
    fn digest<DD: Digest>(&self, hasher: &mut DD) {
        hasher.input(&self.0)
    }
}

impl<D: Digest> PartialEq for BlockID<D> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<D: Digest> Eq for BlockID<D> {}

impl<D: Digest> TryFrom<&[u8]> for BlockID<D> {
    type Error = ConvertError;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        if src.len() != D::OutputSize::to_usize() {
            Err(ConvertError::LengthMismatch(
                D::OutputSize::to_usize(),
                src.len(),
            ))
        } else {
            Ok(Self(GenericArray::clone_from_slice(src)))
        }
    }
}

impl<D: Digest> AsRef<[u8]> for BlockID<D> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<D: Digest> Hash for BlockID<D> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<D: Digest + Debug> Message for BlockID<D>
where
    <D as Digest>::OutputSize: Debug,
    Self: Default,
{
    fn encode_raw<B>(&self, buf: &mut B)
    where
        B: BufMut,
    {
        bytes::encode(1, &self.as_ref().to_vec(), buf)
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
            if vbuf.len() != D::OutputSize::to_usize() {
                return Err(DecodeError::new(alloc::format!(
                    "BlockID: expected {} bytes, got {}",
                    D::OutputSize::to_usize(),
                    vbuf.len()
                )));
            }
            *self = Self(GenericArray::clone_from_slice(&vbuf[..]));
            Ok(())
        } else {
            skip_field(wire_type, tag, buf, ctx)
        }
    }

    fn encoded_len(&self) -> usize {
        bytes::encoded_len(1, &vec![0u8; D::OutputSize::to_usize()])
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
}
