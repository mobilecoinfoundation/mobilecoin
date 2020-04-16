use crate::{
    commitment::Commitment,
    ring_signature::{Error, Scalar, GENERATORS},
};
use core::{convert::TryFrom, fmt};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use digestible::Digestible;
use mcserial::{
    deduce_core_traits_from_public_bytes, prost_message_helper32, try_from_helper32, ReprBytes32,
};
use serde::{Deserialize, Serialize};

/// A Pedersen commitment in compressed Ristretto format.
#[derive(Copy, Clone, Default, Eq, Serialize, Deserialize, Digestible)]
pub struct CompressedCommitment {
    /// A Pedersen commitment `v*G + b*H` to a quantity `v` with blinding `b`,
    pub point: CompressedRistretto,
}

impl CompressedCommitment {
    pub fn new(value: u64, blinding: Scalar) -> Self {
        Self {
            point: GENERATORS.commit(Scalar::from(value), blinding).compress(),
        }
    }
}

impl From<&Commitment> for CompressedCommitment {
    fn from(src: &Commitment) -> Self {
        Self {
            point: src.point.compress(),
        }
    }
}

impl fmt::Debug for CompressedCommitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CompressedCommitment({})",
            hex_fmt::HexFmt(self.point.as_bytes())
        )
    }
}

impl AsRef<[u8; 32]> for CompressedCommitment {
    fn as_ref(&self) -> &[u8; 32] {
        self.point.as_bytes()
    }
}

// Implements Ord, PartialOrd, PartialEq, Hash. Requires AsRef<[u8;32]>.
deduce_core_traits_from_public_bytes! { CompressedCommitment }

impl ReprBytes32 for CompressedCommitment {
    type Error = Error;
    fn to_bytes(&self) -> [u8; 32] {
        self.point.to_bytes()
    }
    fn from_bytes(src: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self {
            point: CompressedRistretto::from_slice(src),
        })
    }
}

// Implements prost::Message. Requires Debug and ReprBytes32.
prost_message_helper32! { CompressedCommitment }

// Implements try_from<&[u8;32]> and try_from<&[u8]>. Requires ReprBytes32.
try_from_helper32! { CompressedCommitment }
