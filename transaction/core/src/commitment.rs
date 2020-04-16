use crate::{
    compressed_commitment::CompressedCommitment,
    ring_signature::{Error, Scalar, GENERATORS},
};
use core::{convert::TryFrom, fmt};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use digestible::Digestible;
use mcserial::{
    deduce_core_traits_from_public_bytes, prost_message_helper32, try_from_helper32, ReprBytes32,
};
use serde::{Deserialize, Serialize};

/// A Pedersen commitment in uncompressed Ristretto format.
#[derive(Copy, Clone, Default, Digestible)]
pub struct Commitment {
    /// A Pedersen commitment `v*G + b*H` to a quantity `v` with blinding `b`,
    pub point: RistrettoPoint,
}

impl Commitment {
    pub fn new(value: u64, blinding: Scalar) -> Self {
        Self {
            point: GENERATORS.commit(Scalar::from(value), blinding),
        }
    }
}

impl TryFrom<&CompressedCommitment> for Commitment {
    type Error = crate::ring_signature::Error;

    fn try_from(src: &CompressedCommitment) -> Result<Self, Self::Error> {
        let point = src.point.decompress().ok_or(Error::InvalidCurvePoint)?;
        Ok(Self { point })
    }
}

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Commitment({})",
            hex_fmt::HexFmt(self.point.compress().as_bytes())
        )
    }
}

// impl AsRef<[u8; 32]> for Commitment {
//     fn as_ref(&self) -> &[u8; 32] {
//         self.point.compress().as_bytes()
//     }
// }
//
// // Implements Ord, PartialOrd, PartialEq, Hash. Requires AsRef<[u8;32]>.
// deduce_core_traits_from_public_bytes! { Commitment }

impl ReprBytes32 for Commitment {
    type Error = Error;
    fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }
    fn from_bytes(src: &[u8; 32]) -> Result<Self, Error> {
        let point = CompressedRistretto::from_slice(src)
            .decompress()
            .ok_or(Error::InvalidCurvePoint)?;
        Ok(Self { point })
    }
}

// Implements prost::Message. Requires Debug and ReprBytes32.
prost_message_helper32! { Commitment }

// Implements try_from<&[u8;32]> and try_from<&[u8]>. Requires ReprBytes32.
try_from_helper32! { Commitment }
