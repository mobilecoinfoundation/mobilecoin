// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::ConvertError;
use alloc::{vec, vec::Vec};
use core::{convert::TryFrom, fmt::Debug};
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_ring_signature::KeyImage;
use mc_transaction_core::{
    mint::{MintTx, ValidatedMintConfigTx},
    tx::TxOut,
};
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

    /// mint-config transactions in this block.
    #[prost(message, repeated, tag = "3")]
    pub validated_mint_config_txs: Vec<ValidatedMintConfigTx>,

    /// Mint transactions in this block.
    #[prost(message, repeated, tag = "4")]
    pub mint_txs: Vec<MintTx>,
}

impl BlockContents {
    /// The Merlin digest of `self`.
    pub fn hash(&self) -> BlockContentsHash {
        BlockContentsHash(self.digest32::<MerlinTranscript>(b"block_contents"))
    }
}

#[repr(transparent)]
#[derive(Clone, Debug, Default, Digestible, Serialize, Deserialize, PartialEq, Eq)]
#[digestible(transparent)]
/// Hash of contents (i.e. transactions) in a block.
pub struct BlockContentsHash(pub [u8; 32]);

impl TryFrom<&[u8]> for BlockContentsHash {
    type Error = ConvertError;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(<[u8; 32] as TryFrom<&[u8]>>::try_from(src).map_err(
            |_| ConvertError::LengthMismatch(core::mem::size_of::<Self>(), src.len()),
        )?))
    }
}

impl AsRef<[u8]> for BlockContentsHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Message for BlockContentsHash {
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
            *self = Self::try_from(&vbuf[..]).map_err(|_| {
                DecodeError::new(alloc::format!(
                    "BlockContentsHash: expected {} bytes, got {}",
                    core::mem::size_of::<Self>(),
                    vbuf.len()
                ))
            })?;
            Ok(())
        } else {
            skip_field(wire_type, tag, buf, ctx)
        }
    }

    fn encoded_len(&self) -> usize {
        bytes::encoded_len(1, &vec![0u8; core::mem::size_of::<Self>()])
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
}
