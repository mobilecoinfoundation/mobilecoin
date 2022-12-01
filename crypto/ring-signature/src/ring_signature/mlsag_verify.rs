// Copyright (c) 2018-2022 The MobileCoin Foundation

//! RingMLSAG verification internals

use curve25519_dalek::ristretto::RistrettoPoint;

use crate::{
    ring_signature::{
        challenge, hash_to_point, CurveScalar, Error, KeyImage, Ring, Scalar, B_BLINDING,
    },
    Commitment, CompressedCommitment,
};

/// MLSAG Verification object
pub struct MlsagVerify<'a, R: Ring> {
    /// Key image to be verified
    pub key_image: &'a KeyImage,
    /// Zero-th challenge scalar
    pub c_zero: &'a CurveScalar,
    /// Signed message.
    pub message: &'a [u8],
    /// A ring of input onetime addresses and amount commitments.
    pub ring: R,
    /// Responses from the signed ring
    pub responses: &'a [CurveScalar],
    /// Output amount commitment
    pub output_commitment: &'a CompressedCommitment,
}

impl<'a, R: Ring> MlsagVerify<'a, R> {
    /// mlsag verification logic, buffer based for no_std compatibility
    pub fn verify(&self, recomputed_c: &mut [Scalar]) -> Result<(), Error> {
        let ring_size = self.ring.size();

        // `responses` must contain `2 * ring_size` elements.
        if self.responses.len() != 2 * ring_size {
            return Err(Error::LengthMismatch(2 * ring_size, self.responses.len()));
        }
        // `recomputed_c` buffer must contain `ring_size` elements.
        if recomputed_c.len() != ring_size {
            return Err(Error::LengthMismatch(ring_size, recomputed_c.len()));
        }

        let G = B_BLINDING;

        // The key image must decompress.
        // This ensures that the key image encodes a valid Ristretto point.
        let I: RistrettoPoint = self
            .key_image
            .point
            .decompress()
            .ok_or(Error::InvalidKeyImage)?;

        // Output commitment must decompress.
        let output_commitment: Commitment = Commitment::try_from(self.output_commitment)?;

        // Ring must decompress.
        // This ensures that each address and commitment encodes a valid Ristretto
        // point.
        self.ring.check()?;

        // Scalars must be canonical.
        if !self.c_zero.scalar.is_canonical() {
            return Err(Error::InvalidCurveScalar);
        }

        // Scalars must be canonical.
        for response in self.responses {
            if !response.scalar.is_canonical() {
                return Err(Error::InvalidCurveScalar);
            }
        }

        // Recompute challenges.
        recomputed_c.iter_mut().for_each(|v| *v = Scalar::zero());

        for i in 0..ring_size {
            let (P_i, input_commitment) = &self.ring.index(i)?;

            let c_i = if i == 0 {
                // Initialize loop using the signature's c_0 term.
                self.c_zero.scalar
            } else {
                recomputed_c[i]
            };

            // c_{i+1} = Hn( m | key_image |  r_{i,0} * G + c_i * P_i | r_{i,0} * Hp(P_i) +
            // c_i * I | r_{i,1} * G + c_i * Z_i )         = Hn( m | key_image |
            // L0            |               R0            |           L1            )
            //
            // where:
            // * P_i is the i^th onetime public key.
            // * I is the key image of the real input's private key,
            // * Z_i is the i^th "commitment to zero" = output_commitment - i^th
            //   input_commitment.

            let L0 = self.responses[2 * i].scalar * G + c_i * P_i.as_ref();
            let R0 = self.responses[2 * i].scalar * hash_to_point(P_i) + c_i * I;
            let L1 = self.responses[2 * i + 1].scalar * G
                + c_i * (output_commitment.point - input_commitment.point);

            recomputed_c[(i + 1) % ring_size] =
                challenge(self.message, &self.key_image, &L0, &R0, &L1);
        }

        let res = match self.c_zero.scalar == recomputed_c[0] {
            true => Ok(()),
            false => Err(Error::InvalidSignature),
        };

        // Clear challenge buffer
        recomputed_c.iter_mut().for_each(|v| *v = Scalar::zero());

        res
    }
}
