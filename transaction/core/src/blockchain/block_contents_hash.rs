use crate::{blake2b_256::Blake2b256, ConvertError};
use core::convert::TryFrom;
use digestible::{Digest, Digestible};
use generic_array::{typenum::Unsigned, GenericArray};
use serde::{Deserialize, Serialize};

#[repr(transparent)]
#[derive(Clone, Debug, Serialize, Deserialize)]
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
