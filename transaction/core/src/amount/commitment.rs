use crate::{
    ring_signature::{Error, Scalar, GENERATORS},
    CompressedCommitment,
};
use core::{convert::TryFrom, fmt};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use mc_crypto_digestible::Digestible;
use mc_util_repr_bytes::{
    derive_prost_message_from_repr_bytes, derive_try_from_slice_from_repr_bytes, typenum::U32,
    GenericArray, ReprBytes,
};

/// A Pedersen commitment in uncompressed Ristretto format.
#[derive(Copy, Clone, Default, Digestible)]
#[digestible(transparent)]
pub struct Commitment {
    /// A Pedersen commitment `v*H + b*G` to a quantity `v` with blinding `b`,
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

impl ReprBytes for Commitment {
    type Error = Error;
    type Size = U32;
    fn to_bytes(&self) -> GenericArray<u8, U32> {
        self.point.compress().to_bytes().into()
    }
    fn from_bytes(src: &GenericArray<u8, U32>) -> Result<Self, Error> {
        let point = CompressedRistretto::from_slice(src.as_slice())
            .decompress()
            .ok_or(Error::InvalidCurvePoint)?;
        Ok(Self { point })
    }
}

derive_prost_message_from_repr_bytes!(Commitment);
derive_try_from_slice_from_repr_bytes!(Commitment);

#[cfg(test)]
#[allow(non_snake_case)]
mod commitment_tests {
    use crate::{
        ring_signature::{Scalar, GENERATORS},
        Commitment,
    };
    use curve25519_dalek::ristretto::RistrettoPoint;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    #[test]
    // Commitment::new should create the correct RistrettoPoint.
    fn test_new() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let value = rng.next_u64();
        let blinding = Scalar::random(&mut rng);

        let commitment = Commitment::new(value, blinding);

        let expected_point: RistrettoPoint = {
            let H = GENERATORS.B;
            let G = GENERATORS.B_blinding;
            Scalar::from(value) * H + blinding * G
        };

        assert_eq!(commitment.point, expected_point);
    }
}
