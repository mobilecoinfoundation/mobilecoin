// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::ConvertError;
use alloc::{vec, vec::Vec};
use core::{
    convert::TryFrom,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::Hash,
};
use mc_crypto_digestible::Digestible;
use prost::{
    bytes::{Buf, BufMut},
    encoding::{bytes, skip_field, DecodeContext, WireType},
    DecodeError, Message,
};
use serde::{Deserialize, Serialize};

#[repr(transparent)]
#[derive(Clone, Default, Debug, Digestible, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[digestible(transparent)]
/// Identifies a block with its hash.
pub struct BlockID(pub [u8; 32]);

impl TryFrom<&[u8]> for BlockID {
    type Error = ConvertError;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(<[u8; 32] as TryFrom<&[u8]>>::try_from(src).map_err(
            |_| ConvertError::LengthMismatch(core::mem::size_of::<Self>(), src.len()),
        )?))
    }
}

impl AsRef<[u8]> for BlockID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for BlockID {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", hex_fmt::HexFmt(&self.0),)
    }
}

impl Message for BlockID {
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
                    "BlockID: expected {} bytes, got {}",
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
