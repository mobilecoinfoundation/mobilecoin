// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    ring_signature::{Error, PedersenGens, Scalar},
    Commitment,
};
use curve25519_dalek::ristretto::CompressedRistretto;
use mc_crypto_digestible::Digestible;
use mc_util_repr_bytes::{
    derive_core_cmp_from_as_ref, derive_debug_and_display_hex_from_as_ref,
    derive_prost_message_from_repr_bytes, derive_try_from_slice_from_repr_bytes, typenum::U32,
    GenericArray, ReprBytes,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A Pedersen commitment in compressed Ristretto format.
#[derive(Copy, Clone, Default, Deserialize, Digestible, Serialize, Zeroize)]
#[digestible(transparent)]
pub struct CompressedCommitment {
    /// A Pedersen commitment `v*H + b*G` to a quantity `v` with blinding `b`,
    pub point: CompressedRistretto,
}

impl CompressedCommitment {
    /// Create a new compressed commitment from value, blinding factor, and
    /// pedersen generators
    pub fn new(value: u64, blinding: Scalar, generator: &PedersenGens) -> Self {
        Self::from(&Commitment::new(value, blinding, generator))
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

derive_core_cmp_from_as_ref!(CompressedCommitment, [u8; 32]);
derive_debug_and_display_hex_from_as_ref!(CompressedCommitment);
derive_prost_message_from_repr_bytes!(CompressedCommitment);
derive_try_from_slice_from_repr_bytes!(CompressedCommitment);

#[cfg(test)]
#[allow(non_snake_case)]
mod compressed_commitment_tests {
    use crate::{
        ring_signature::{generators, Scalar},
        CompressedCommitment,
    };
    use curve25519_dalek::ristretto::CompressedRistretto;
    use mc_util_test_helper::{run_with_several_seeds, RngCore};

    #[test]
    // Commitment::new should create the correct RistrettoPoint.
    fn test_new() {
        run_with_several_seeds(|mut rng| {
            let value = rng.next_u64();
            let blinding = Scalar::random(&mut rng);
            let generator = generators(0);

            let commitment = CompressedCommitment::new(value, blinding, &generator);

            let expected_point: CompressedRistretto = {
                let H = generator.B;
                let G = generator.B_blinding;
                let point = Scalar::from(value) * H + blinding * G;
                point.compress()
            };

            assert_eq!(commitment.point, expected_point);
        })
    }
}
