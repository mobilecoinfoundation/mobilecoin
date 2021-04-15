// Copyright (c) 2018-2021 The MobileCoin Foundation

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::convert::TryFrom;

use blake2::{Blake2b, Digest};
use curve25519_dalek::ristretto::RistrettoPoint;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
use prost::Message;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    domain_separators::RING_MLSAG_CHALLENGE_DOMAIN_TAG,
    ring_signature::{hash_to_point, CurveScalar, Error, KeyImage, Scalar, GENERATORS},
    Commitment, CompressedCommitment,
};

/// MLSAG for a ring of public keys and amount commitments.
/// Note: Serialize and Deserialize appear to be cruft left over from
/// sdk_json_interface.
#[derive(Clone, Digestible, PartialEq, Eq, Serialize, Deserialize, Message)]
pub struct RingMLSAG {
    /// The initial challenge `c[0]`.
    #[prost(message, required, tag = "1")]
    pub c_zero: CurveScalar,

    /// Responses `r_{0,0}, r_{0,1}, ... , r_{ring_size-1,0},
    /// r_{ring_size-1,1}`.
    #[prost(message, repeated, tag = "2")]
    pub responses: Vec<CurveScalar>,

    /// Key image "spent" by this signature.
    #[prost(message, required, tag = "3")]
    pub key_image: KeyImage,
}

impl RingMLSAG {
    // Sign a ring of input addresses and amount commitments.
    //
    // Sign a ring of input addresses and amount commitments using a modified MLSAG
    // that omits the "key image" term for the amount commitments (which do not need
    // to be linkable).
    //
    // # Arguments
    // * `message` - Message to be signed.
    // * `ring` - A ring of input onetime addresses and amount commitments.
    // * `real_index` - The index in the ring of the real input.
    // * `onetime_private_key` - The real input's private key.
    // * `value` - Value of the real input.
    // * `blinding` - Blinding of the real input.
    // * `output_blinding` - The output amount's blinding factor.
    // * `rng` - Randomness.
    pub fn sign<CSPRNG: RngCore + CryptoRng>(
        message: &[u8],
        ring: &[(CompressedRistrettoPublic, CompressedCommitment)],
        real_index: usize,
        onetime_private_key: &RistrettoPrivate,
        value: u64,
        blinding: &Scalar,
        output_blinding: &Scalar,
        rng: &mut CSPRNG,
    ) -> Result<Self, Error> {
        RingMLSAG::sign_with_balance_check(
            message,
            ring,
            real_index,
            onetime_private_key,
            value,
            blinding,
            output_blinding,
            true,
            rng,
        )
    }

    // Sign a ring of input addresses and amount commitments.
    //
    // Sign a ring of input addresses and amount commitments using a modified MLSAG
    // that omits the "key image" term for the amount commitments (which do not need
    // to be linkable).
    //
    // # Arguments
    // * `message` - Message to be signed.
    // * `ring` - A ring of input onetime addresses and amount commitments.
    // * `real_index` - The index in the ring of the real input.
    // * `onetime_private_key` - The real input's private key.
    // * `value` - Value of the real input.
    // * `blinding` - Blinding of the real input.
    // * `output_blinding` - The output amount's blinding factor.
    // * `check_value_is_preserved` - If true, check that the value of inputs equals
    //   value of outputs.
    // * `rng` - Randomness.
    fn sign_with_balance_check<CSPRNG: RngCore + CryptoRng>(
        message: &[u8],
        ring: &[(CompressedRistrettoPublic, CompressedCommitment)],
        real_index: usize,
        onetime_private_key: &RistrettoPrivate,
        value: u64,
        blinding: &Scalar,
        output_blinding: &Scalar,
        check_value_is_preserved: bool,
        rng: &mut CSPRNG,
    ) -> Result<Self, Error> {
        let ring_size = ring.len();

        if real_index >= ring_size {
            return Err(Error::IndexOutOfBounds);
        }

        let G = GENERATORS.B_blinding;

        let key_image = KeyImage::from(onetime_private_key);

        // The uncompressed key_image.
        let I: RistrettoPoint = key_image.point.decompress().ok_or(Error::InvalidKeyImage)?;

        // Uncompressed output commitment.
        // This ensures that each address and commitment encodes a valid Ristretto
        // point.
        let output_commitment = Commitment::new(value, *output_blinding);

        // Ring must decompress.
        let decompressed_ring = decompress_ring(ring)?;

        // Challenges `c_0, ... c_{ring_size - 1}`.
        let mut c: Vec<Scalar> = vec![Scalar::zero(); ring_size];

        // Responses `r_{0,0}, r_{0,1}, ... , r_{ring_size-1,0}, r_{ring_size-1,1}`.
        let mut r: Vec<Scalar> = vec![Scalar::zero(); 2 * ring_size];
        for i in 0..ring_size {
            if i == real_index {
                continue;
            }
            r[2 * i] = Scalar::random(rng);
            r[2 * i + 1] = Scalar::random(rng);
        }

        let alpha_0 = Zeroizing::new(Scalar::random(rng));
        let alpha_1 = Zeroizing::new(Scalar::random(rng));

        for n in 0..ring_size {
            // Iterate around the ring, starting at real_index.
            let i = (real_index + n) % ring_size;
            let (P_i, input_commitment) = &decompressed_ring[i];

            let (L0, R0, L1) = if i == real_index {
                // c_{i+1} = Hn( m | key_image | alpha_0 * G | alpha_0 * Hp(P_i) | alpha_1 * G )
                //         = Hn( m | key_image |      L0     |         R0        |      L1     )
                //
                // where P_i is the i^th onetime public key.
                // There is no R1 term because no key image is needed for the commitment to
                // zero.

                let L0 = *alpha_0 * G;
                let R0 = *alpha_0 * hash_to_point(&P_i);
                let L1 = *alpha_1 * G;
                (L0, R0, L1)
            } else {
                // c_{i+1} = Hn( m | key_image | r_{i,0} * G + c_i * P_i | r_{i,0} * Hp(P_i) +
                // c_i * I | r_{i,1} * G + c_i * Z_i )         = Hn( m |
                // key_image |           L0            |               R0            |
                // L1          )
                //
                // where:
                // * P_i is the i^th onetime public key.
                // * I is the key image of the real input's private key,
                // * Z_i is the i^th "commitment to zero" = output_commitment -
                //   input_commitment.
                //
                // There is no R1 term because no key image is needed for the commitment to
                // zero.

                let L0 = r[2 * i] * G + c[i] * P_i.as_ref();
                let R0 = r[2 * i] * hash_to_point(&P_i) + c[i] * I;
                let L1 =
                    r[2 * i + 1] * G + c[i] * (output_commitment.point - input_commitment.point);
                (L0, R0, L1)
            };

            c[(i + 1) % ring_size] = challenge(message, &key_image, &L0, &R0, &L1);
        }

        // "Close the loop" by computing responses for the real index.

        let s: Scalar = *onetime_private_key.as_ref();
        r[2 * real_index] = *alpha_0 - c[real_index] * s;

        let z: Scalar = output_blinding - blinding;
        r[2 * real_index + 1] = *alpha_1 - c[real_index] * z;

        if check_value_is_preserved {
            let (_, input_commitment) = decompressed_ring[real_index];
            let difference: RistrettoPoint = output_commitment.point - input_commitment.point;
            if difference != (z * G) {
                return Err(Error::ValueNotConserved);
            }
        }

        let responses: Vec<CurveScalar> = r.into_iter().map(CurveScalar::from).collect();

        Ok(RingMLSAG {
            c_zero: CurveScalar::from(c[0]),
            responses,
            key_image,
        })
    }

    /// Verify MLSAG signature.
    ///
    /// # Arguments
    /// * `message` - Message to be signed.
    /// * `ring` - A ring of input onetime addresses and amount commitments.
    /// * `output_commitment` - Output amount commitment.
    pub fn verify(
        &self,
        message: &[u8],
        ring: &[(CompressedRistrettoPublic, CompressedCommitment)],
        output_commitment: &CompressedCommitment,
    ) -> Result<(), Error> {
        let ring_size = ring.len();
        // `responses` must contain `2 * ring_size` elements.
        if self.responses.len() != 2 * ring_size {
            return Err(Error::LengthMismatch(2 * ring_size, self.responses.len()));
        }

        let G = GENERATORS.B_blinding;

        // The key image must decompress.
        // This ensures that the key image encodes a valid Ristretto point.
        let I: RistrettoPoint = self
            .key_image
            .point
            .decompress()
            .ok_or(Error::InvalidKeyImage)?;

        let r: Vec<Scalar> = self
            .responses
            .iter()
            .map(|response| response.scalar)
            .collect();

        // Output commitment must decompress.
        let output_commitment: Commitment = Commitment::try_from(output_commitment)?;

        // Ring must decompress.
        // This ensures that each address and commitment encodes a valid Ristretto
        // point.
        let decompressed_ring = decompress_ring(ring)?;

        // Scalars must be canonical.
        if !self.c_zero.scalar.is_canonical() {
            return Err(Error::InvalidCurveScalar);
        }

        // Scalars must be canonical.
        for response in &self.responses {
            if !response.scalar.is_canonical() {
                return Err(Error::InvalidCurveScalar);
            }
        }

        // Recompute challenges.
        let mut recomputed_c = vec![Scalar::zero(); ring.len()];

        for (i, (P_i, input_commitment)) in decompressed_ring.iter().enumerate() {
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

            let L0 = r[2 * i] * G + c_i * P_i.as_ref();
            let R0 = r[2 * i] * hash_to_point(P_i) + c_i * I;
            let L1 = r[2 * i + 1] * G + c_i * (output_commitment.point - input_commitment.point);

            recomputed_c[(i + 1) % ring_size] = challenge(message, &self.key_image, &L0, &R0, &L1);
        }

        if self.c_zero.scalar == recomputed_c[0] {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

// Compute the "challenge" H( message | key_image | L0 | R0 | L1 ).
fn challenge(
    message: &[u8],
    key_image: &KeyImage,
    L0: &RistrettoPoint,
    R0: &RistrettoPoint,
    L1: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Blake2b::new();
    hasher.update(&RING_MLSAG_CHALLENGE_DOMAIN_TAG);
    hasher.update(message);
    hasher.update(key_image);
    hasher.update(L0.compress().as_bytes());
    hasher.update(R0.compress().as_bytes());
    hasher.update(L1.compress().as_bytes());
    Scalar::from_hash::<Blake2b>(hasher)
}

fn decompress_ring(
    ring: &[(CompressedRistrettoPublic, CompressedCommitment)],
) -> Result<Vec<(RistrettoPublic, Commitment)>, Error> {
    // Ring must decompress.
    let mut decompressed_ring: Vec<(RistrettoPublic, Commitment)> = Vec::new();
    for (compressed_address, compressed_commitment) in ring {
        let ristretto_public =
            RistrettoPublic::try_from(compressed_address).map_err(|_e| Error::InvalidCurvePoint)?;
        let commitment = Commitment::try_from(compressed_commitment)?;
        decompressed_ring.push((ristretto_public, commitment));
    }
    Ok(decompressed_ring)
}

#[cfg(test)]
mod mlsag_tests {
    use crate::{
        ring_signature::{mlsag::RingMLSAG, CurveScalar, Error, KeyImage, Scalar},
        CompressedCommitment,
    };
    use alloc::vec::Vec;
    use curve25519_dalek::ristretto::CompressedRistretto;
    use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
    use mc_util_from_random::FromRandom;
    use proptest::prelude::*;
    use rand::{rngs::StdRng, CryptoRng, SeedableRng};
    use rand_core::RngCore;

    extern crate std;

    #[derive(Debug)]
    struct RingMLSAGParameters {
        message: [u8; 32],
        ring: Vec<(CompressedRistrettoPublic, CompressedCommitment)>,
        real_index: usize,
        onetime_private_key: RistrettoPrivate,
        value: u64,
        blinding: Scalar,
        pseudo_output_blinding: Scalar,
    }

    impl RingMLSAGParameters {
        fn random<RNG: RngCore + CryptoRng>(
            num_mixins: usize,
            pseudo_output_blinding: Scalar,
            rng: &mut RNG,
        ) -> Self {
            let mut message = [0u8; 32];
            rng.fill_bytes(&mut message);

            let mut ring: Vec<(CompressedRistrettoPublic, CompressedCommitment)> = Vec::new();
            for _i in 0..num_mixins {
                let address = CompressedRistrettoPublic::from(RistrettoPublic::from_random(rng));
                let commitment = {
                    let value = rng.next_u64();
                    let blinding = Scalar::random(rng);
                    CompressedCommitment::new(value, blinding)
                };
                ring.push((address, commitment));
            }

            // The real input.
            let onetime_private_key = RistrettoPrivate::from_random(rng);
            let onetime_public_key =
                CompressedRistrettoPublic::from(RistrettoPublic::from(&onetime_private_key));

            let value = rng.next_u64();
            let blinding = Scalar::random(rng);
            let commitment = CompressedCommitment::new(value, blinding);

            let real_index = rng.next_u64() as usize % (num_mixins + 1);
            ring.insert(real_index, (onetime_public_key, commitment));
            assert_eq!(ring.len(), num_mixins + 1);

            Self {
                message,
                ring,
                real_index,
                onetime_private_key,
                value,
                blinding,
                pseudo_output_blinding,
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(3))]

        #[test]
        // `sign` should return a signature with 2*ring_size responses.
        fn test_signature_responses_has_correct_length(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);

            let ring_mlsag_parameters =
                RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = RingMLSAG::sign(
                &ring_mlsag_parameters.message,
                &ring_mlsag_parameters.ring,
                ring_mlsag_parameters.real_index,
                &ring_mlsag_parameters.onetime_private_key,
                ring_mlsag_parameters.value,
                &ring_mlsag_parameters.blinding,
                &ring_mlsag_parameters.pseudo_output_blinding,
                &mut rng,
            )
            .unwrap();

            let ring_size = num_mixins + 1;
            assert_eq!(signature.responses.len(), 2 * ring_size);

            // All responses should be non-zero.
            for r in &signature.responses {
                assert_ne!(r.scalar, Scalar::zero());
            }
        }

        #[test]
        // `sign` should return a signature with correct key image.
        fn test_sign_produces_correct_key_image(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = RingMLSAG::sign(
                &params.message,
                &params.ring,
                params.real_index,
                &params.onetime_private_key,
                params.value,
                &params.blinding,
                &params.pseudo_output_blinding,
                &mut rng,
            )
            .unwrap();

            let expected_key_image = KeyImage::from(&params.onetime_private_key);
            assert_eq!(signature.key_image, expected_key_image);
        }

        #[test]
        // `sign` should return an Error if the input and output have different values.
        fn test_sign_returns_error_if_value_is_not_conserved(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);
            let wrong_value = rng.next_u64();

            let result = RingMLSAG::sign(
                &params.message,
                &params.ring,
                params.real_index,
                &params.onetime_private_key,
                wrong_value,
                &params.blinding,
                &params.pseudo_output_blinding,
                &mut rng,
            );

            match result {
                Err(Error::ValueNotConserved) => {} // Expected
                _ => panic!(),
            }
        }

        #[test]
        fn test_sign_returns_error_if_real_index_is_out_of_bounds(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);
            // The ring contains num_mixins + 1 elements, with indices 0..num_mixins.
            // This is the smallest out of bounds index.
            let wrong_real_index = num_mixins + 1;

            let result = RingMLSAG::sign(
                &params.message,
                &params.ring,
                wrong_real_index,
                &params.onetime_private_key,
                params.value,
                &params.blinding,
                &params.pseudo_output_blinding,
                &mut rng,
            );

            match result {
                Err(Error::IndexOutOfBounds) => {} // Expected
                _ => panic!(),
            }
        }

        #[test]
        // `verify` should accept valid signatures.
        fn test_verify_accepts_valid_signatures(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = RingMLSAG::sign(
                &params.message,
                &params.ring,
                params.real_index,
                &params.onetime_private_key,
                params.value,
                &params.blinding,
                &params.pseudo_output_blinding,
                &mut rng,
            )
            .unwrap();

            let output_commitment = CompressedCommitment::new(params.value, params.pseudo_output_blinding);

            assert!(signature
                .verify(&params.message, &params.ring, &output_commitment)
                .is_ok());
        }

        #[test]
        // `verify` should reject a signature signed with wrong onetime_private_key.
        fn test_verify_rejects_signature_signed_with_wrong_onetime_private_key(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);
            let wrong_onetime_private_key = RistrettoPrivate::from_random(&mut rng);

            let signature = RingMLSAG::sign(
                &params.message,
                &params.ring,
                params.real_index,
                &wrong_onetime_private_key,
                params.value,
                &params.blinding,
                &params.pseudo_output_blinding,
                &mut rng,
            )
            .unwrap();

            let output_commitment = CompressedCommitment::new(params.value, params.pseudo_output_blinding);

            match signature.verify(&params.message, &params.ring, &output_commitment) {
                Err(Error::InvalidSignature) => {} // This is expected.
                _ => panic!(),
            }
        }

        #[test]
        // `verify` should reject a signature signed with wrong amount secrets.
        fn test_verify_rejects_signature_signed_with_wrong_amount_secrets(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            // Sign with an input value that differs from the real input's amount commitment.
            {
                let wrong_value = rng.next_u64();
                // Disable value checking in order to create an invalid signature.
                let invalid_signature = RingMLSAG::sign_with_balance_check(
                    &params.message,
                    &params.ring,
                    params.real_index,
                    &params.onetime_private_key,
                    wrong_value,
                    &params.blinding,
                    &params.pseudo_output_blinding,
                    false,
                    &mut rng,
                )
                .unwrap();

                let output_commitment = CompressedCommitment::new(wrong_value, params.pseudo_output_blinding);

                let result =
                    invalid_signature.verify(&params.message, &params.ring, &output_commitment);

                match result {
                    Err(Error::InvalidSignature) => {} // This is expected.
                    _ => panic!(),
                }
            }

            // Sign with an input blinding that differs from the real input's amount commitment.
            {
                let wrong_blinding = Scalar::random(&mut rng);

                // Disable value checking in order to create an invalid signature.
                let invalid_signature = RingMLSAG::sign_with_balance_check(
                    &params.message,
                    &params.ring,
                    params.real_index,
                    &params.onetime_private_key,
                    params.value,
                    &wrong_blinding,
                    &params.pseudo_output_blinding,
                    false,
                    &mut rng,
                )
                .unwrap();

                let output_commitment = CompressedCommitment::new(params.value, wrong_blinding);

                let result =
                    invalid_signature.verify(&params.message, &params.ring, &output_commitment);

                match result {
                    Err(Error::InvalidSignature) => {} // This is expected.
                    _ => panic!(),
                }
            }
        }

        #[test]
        // `verify` should reject a signature if the key image is not canonically encoded.
        fn test_verify_rejects_noncanonical_key_image(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let mut signature = RingMLSAG::sign(
                &params.message,
                &params.ring,
                params.real_index,
                &params.onetime_private_key,
                params.value,
                &params.blinding,
                &params.pseudo_output_blinding,
                &mut rng,
            )
            .unwrap();

            // Replace the key image with a non-canonical compressed Ristretto point.
            // This is constants::EDWARDS_D.to_bytes(), which is a negative point, so decompression should fail.
            // Edwards `d` value, equal to `-121665/121666 mod p`.
            let edwards_d : [u8; 32] = [163, 120, 89, 19, 202, 77, 235, 117, 171, 216, 65, 65, 77, 10, 112, 0, 152, 232, 121, 119, 121, 64, 199, 140, 115, 254, 111, 43, 238, 108, 3, 82];
            let bad_compressed = CompressedRistretto(edwards_d);
            assert!(bad_compressed.decompress().is_none());

            signature.key_image = KeyImage{point: bad_compressed};

            let output_commitment = CompressedCommitment::new(params.value, params.pseudo_output_blinding);

            match signature.verify(&params.message, &params.ring, &output_commitment) {
                Err(Error::InvalidKeyImage) => {} // This is expected.
                Err(e) => panic!("Unexpected error {}", e),
                Ok(()) => panic!("Signature should be rejected."),
            }
        }

        #[test]
        // `verify` should reject a signature with modified key image.
        fn test_verify_rejects_modified_key_image(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let mut signature = RingMLSAG::sign(
                &params.message,
                &params.ring,
                params.real_index,
                &params.onetime_private_key,
                params.value,
                &params.blinding,
                &params.pseudo_output_blinding,
                &mut rng,
            )
            .unwrap();

            // Modify the key image.
            let wrong_key_image = KeyImage::from(rng.next_u64());
            signature.key_image = wrong_key_image;

            let output_commitment = CompressedCommitment::new(params.value, params.pseudo_output_blinding);

            match signature.verify(&params.message, &params.ring, &output_commitment) {
                Err(Error::InvalidSignature) => {} // This is expected.
                _ => panic!(),
            }
        }

        #[test]
        // `verify` should reject a signature if the message is modified.
        fn test_verify_rejects_modified_message(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = RingMLSAG::sign(
                &params.message,
                &params.ring,
                params.real_index,
                &params.onetime_private_key,
                params.value,
                &params.blinding,
                &params.pseudo_output_blinding,
                &mut rng,
            )
            .unwrap();

            // Modify the message.
            let mut wrong_message = [0u8; 32];
            rng.fill_bytes(&mut wrong_message);

            let output_commitment = CompressedCommitment::new(params.value, params.pseudo_output_blinding);

            let result = signature.verify(&wrong_message, &params.ring, &output_commitment);

            match result {
                Err(Error::InvalidSignature) => {} // This is expected.
                _ => panic!(),
            }
        }

        #[test]
        // `verify` should reject a signature if the ring is modified.
        fn test_verify_rejects_modified_ring(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let mut params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = RingMLSAG::sign(
                &params.message,
                &params.ring,
                params.real_index,
                &params.onetime_private_key,
                params.value,
                &params.blinding,
                &params.pseudo_output_blinding,
                &mut rng,
            )
            .unwrap();

            let output_commitment = CompressedCommitment::new(params.value, params.pseudo_output_blinding);

            // Modify a ring element's public key.
            {
                let index = (rng.next_u64() as usize) % num_mixins;
                params.ring[index].0 = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));

                let result = signature.verify(&params.message, &params.ring, &output_commitment);

                match result {
                    Err(Error::InvalidSignature) => {} // This is expected.
                    _ => panic!(),
                }
            }

            // Modify a ring element's amount commitment.
            {
                let index = (rng.next_u64() as usize) % num_mixins;
                let value = rng.next_u64();
                let blinding = Scalar::random(&mut rng);
                params.ring[index].1 = CompressedCommitment::new(value, blinding);

                let result = signature.verify(&params.message, &params.ring, &output_commitment);

                match result {
                    Err(Error::InvalidSignature) => {} // This is expected.
                    _ => panic!(),
                }
            }
        }

        #[test]
        // `verify` should reject a signature if the output commitment is modified.
        fn test_verify_rejects_modified_output_commitment(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
           let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = RingMLSAG::sign(
                &params.message,
                &params.ring,
                params.real_index,
                &params.onetime_private_key,
                params.value,
                &params.blinding,
                &params.pseudo_output_blinding,
                &mut rng,
            )
            .unwrap();

            // The output_commitment should match the value and pseudo_output_blinding used by the signature.
            // Here, the output_commitment uses a different value.
            let wrong_output_commitment = CompressedCommitment::new(rng.next_u64(), params.pseudo_output_blinding);

            let result = signature.verify(&params.message, &params.ring, &wrong_output_commitment);

            match result {
                Err(Error::InvalidSignature) => {} // This is expected.
                _ => panic!(),
            }
        }

        #[test]
        fn test_verify_rejects_signature_with_wrong_number_of_responses(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);

            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = RingMLSAG::sign(
                &params.message,
                &params.ring,
                params.real_index,
                &params.onetime_private_key,
                params.value,
                &params.blinding,
                &params.pseudo_output_blinding,
                &mut rng,
            )
            .unwrap();

            let output_commitment = CompressedCommitment::new(params.value, params.pseudo_output_blinding);

            // Modify the signature to have too few responses.
            {
                let mut invalid_signature = signature.clone();
                invalid_signature.responses.pop();

                let result =
                    invalid_signature.verify(&params.message, &params.ring, &output_commitment);

                match result {
                    Err(Error::LengthMismatch(_, _)) => {} // This is expected.
                    _ => panic!(),
                }
            }

            // Modify the signature to have too many responses.
            {
                let mut invalid_signature = signature.clone();
                invalid_signature.responses.push(CurveScalar::from_random(&mut rng));

                let result =
                    invalid_signature.verify(&params.message, &params.ring, &output_commitment);

                match result {
                    Err(Error::LengthMismatch(_, _)) => {} // This is expected.
                    _ => panic!(),
                }
            }
        }

        #[test]
        // decode(encode(&signature)) should be the identity function.
        fn test_encode_decode(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = RingMLSAG::sign(
                &params.message,
                &params.ring,
                params.real_index,
                &params.onetime_private_key,
                params.value,
                &params.blinding,
                &params.pseudo_output_blinding,
                &mut rng,
            )
            .unwrap();

            use mc_util_serial::prost::Message;

            // The encoded bytes should have the correct length.
            let bytes = mc_util_serial::encode(&signature);
            assert_eq!(bytes.len(), signature.encoded_len());

            // decode(encode(&signature)) should be the identity function.
            let recovered_signature = mc_util_serial::decode(&bytes).unwrap();
            assert_eq!(signature, recovered_signature);
        }

    } // end proptest!
}
