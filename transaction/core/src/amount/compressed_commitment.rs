use crate::{
    ring_signature::{Error, Scalar, GENERATORS},
    Commitment,
};
use core::fmt;
use curve25519_dalek::ristretto::CompressedRistretto;
use mc_crypto_digestible::Digestible;
use mc_util_repr_bytes::{
    derive_core_cmp_from_as_ref, derive_prost_message_from_repr_bytes,
    derive_try_from_slice_from_repr_bytes, typenum::U32, GenericArray, ReprBytes,
};
use serde::{Deserialize, Serialize};

/// A Pedersen commitment in compressed Ristretto format.
#[derive(Copy, Clone, Default, Eq, Serialize, Deserialize, Digestible)]
#[digestible(transparent)]
pub struct CompressedCommitment {
    /// A Pedersen commitment `v*H + b*G` to a quantity `v` with blinding `b`,
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
impl From<&CompressedRistretto> for CompressedCommitment {
    fn from(source: &CompressedRistretto) -> Self {
        Self { point: *source }
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

impl From<&[u8; 32]> for CompressedCommitment {
    fn from(src: &[u8; 32]) -> Self {
        Self {
            point: CompressedRistretto::from_slice(src),
        }
    }
}

// Implements Ord, PartialOrd, PartialEq, Hash.
derive_core_cmp_from_as_ref!(CompressedCommitment, [u8; 32]);

impl ReprBytes for CompressedCommitment {
    type Error = Error;
    type Size = U32;
    fn to_bytes(&self) -> GenericArray<u8, U32> {
        self.point.to_bytes().into()
    }
    fn from_bytes(src: &GenericArray<u8, U32>) -> Result<Self, Error> {
        Ok(Self {
            point: CompressedRistretto::from_slice(src.as_slice()),
        })
    }
}

derive_prost_message_from_repr_bytes!(CompressedCommitment);
derive_try_from_slice_from_repr_bytes!(CompressedCommitment);

#[cfg(test)]
#[allow(non_snake_case)]
mod compressed_commitment_tests {
    use crate::{
        ring_signature::{Scalar, GENERATORS},
        CompressedCommitment,
    };
    use curve25519_dalek::ristretto::CompressedRistretto;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    #[test]
    // Commitment::new should create the correct RistrettoPoint.
    fn test_new() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let value = rng.next_u64();
        let blinding = Scalar::random(&mut rng);

        let commitment = CompressedCommitment::new(value, blinding);

        let expected_point: CompressedRistretto = {
            let H = GENERATORS.B;
            let G = GENERATORS.B_blinding;
            let point = Scalar::from(value) * H + blinding * G;
            point.compress()
        };

        assert_eq!(commitment.point, expected_point);
    }
}
