use crate::{blake2b_256::Blake2b256, ConvertError};
use core::{
    convert::TryFrom,
    fmt::Debug,
    hash::{Hash, Hasher},
};
use digestible::{Digest, Digestible};
use generic_array::{typenum::Unsigned, GenericArray};
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
