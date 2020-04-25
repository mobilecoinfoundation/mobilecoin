use crate::{
    compressed_commitment::CompressedCommitment,
    ring_signature::{Error, Scalar, GENERATORS},
};
use core::{convert::TryFrom, fmt};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use mc_crypto_digestible::Digestible;
use mc_util_serial::{prost_message_helper32, try_from_helper32, ReprBytes32};

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
            let G = GENERATORS.B;
            let H = GENERATORS.B_blinding;
            Scalar::from(value) * G + blinding * H
        };

        assert_eq!(commitment.point, expected_point);
    }
}
