// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::{ring_signature::KeyImage, tx::TxOut, ConvertError};
use alloc::{vec, vec::Vec};
use core::{convert::TryFrom, fmt::Debug};
use generic_array::{typenum::Unsigned, GenericArray};
use mc_crypto_digestible::{Digest, Digestible};
use mc_crypto_hashes::Blake2b256;
use prost::{
    bytes::{Buf, BufMut},
    encoding::{bytes, skip_field, DecodeContext, WireType},
    DecodeError, Message,
};
use serde::{Deserialize, Serialize};

/// The contents of a Block.
#[derive(Clone, PartialEq, Eq, Digestible, Serialize, Deserialize, Message)]
pub struct BlockContents {
    /// Key images "spent" by this block.
    #[prost(message, repeated, tag = "1")]
    pub key_images: Vec<KeyImage>,

    /// Outputs minted by this block.
    #[prost(message, repeated, tag = "2")]
    pub outputs: Vec<TxOut>,
}

impl BlockContents {
    pub fn new(key_images: Vec<KeyImage>, outputs: Vec<TxOut>) -> Self {
        Self {
            key_images,
            outputs,
        }
    }

    /// The Blake2B256 digest of `self`.
    pub fn hash(&self) -> BlockContentsHash {
        BlockContentsHash(self.digest_with::<Blake2b256>())
    }
}

#[repr(transparent)]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
/// Hash of contents (i.e. transactions) in a block.
pub struct BlockContentsHash<D: Digest = Blake2b256>(pub GenericArray<u8, D::OutputSize>);

impl<D: Digest> Digestible for BlockContentsHash<D> {
    fn digest<DD: Digest>(&self, hasher: &mut DD) {
        hasher.input(&self.0)
    }
}

impl<D: Digest> PartialEq for BlockContentsHash<D> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<D: Digest> Eq for BlockContentsHash<D> {}

impl<D: Digest> TryFrom<&[u8]> for BlockContentsHash<D> {
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

impl<D: Digest> AsRef<[u8]> for BlockContentsHash<D> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<D: Digest + Debug> Message for BlockContentsHash<D>
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
                    "BlockContentsHash: expected {} bytes, got {}",
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
