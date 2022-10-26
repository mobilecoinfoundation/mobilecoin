// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};

use alloc::vec::Vec;
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use mc_crypto_digestible::Digestible;

#[cfg(feature = "prost")]
use prost::Message;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    ring_signature::{
        mlsag_sign::MlsagSignParams, mlsag_verify::MlsagVerify, CurveScalar, Error, KeyImage,
        PedersenGens, Scalar,
    },
    Commitment, CompressedCommitment, ReducedTxOut,
};

/// MLSAG for a ring of public keys and amount commitments.
/// Note: Serialize and Deserialize appear to be cruft left over from
/// sdk_json_interface.
#[derive(Clone, Digestible, PartialEq, Eq)]
#[cfg_attr(feature = "prost", derive(Message))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct RingMLSAG {
    /// The initial challenge `c[0]`.
    #[cfg_attr(feature = "prost", prost(message, required, tag = "1"))]
    pub c_zero: CurveScalar,

    /// Responses `r_{0,0}, r_{0,1}, ... , r_{ring_size-1,0},
    /// r_{ring_size-1,1}`.
    #[cfg_attr(feature = "prost", prost(message, repeated, tag = "2"))]
    pub responses: Vec<CurveScalar>,

    /// Key image "spent" by this signature.
    #[cfg_attr(feature = "prost", prost(message, required, tag = "3"))]
    pub key_image: KeyImage,
}

impl RingMLSAG {
    /// Sign a ring of input addresses and amount commitments.
    ///
    /// Sign a ring of input addresses and amount commitments using a modified
    /// MLSAG that omits the "key image" term for the amount commitments
    /// (which do not need to be linkable).
    ///
    /// # Arguments
    /// * `message` - Message to be signed.
    /// * `ring` - A ring of reduced TxOuts
    /// * `real_index` - The index in the ring of the real input.
    /// * `onetime_private_key` - The real input's private key.
    /// * `value` - Value of the real input.
    /// * `blinding` - Blinding of the real input.
    /// * `output_blinding` - The output amount's blinding factor.
    /// * `generator` - The pedersen generator to use for this commitment and
    ///   signature
    /// * `rng` - Randomness.
    pub fn sign(
        message: &[u8],
        ring: &[ReducedTxOut],
        real_index: usize,
        onetime_private_key: &RistrettoPrivate,
        value: u64,
        blinding: &Scalar,
        output_blinding: &Scalar,
        generator: &PedersenGens,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Self, Error> {
        RingMLSAG::sign_with_balance_check(
            message,
            ring,
            real_index,
            onetime_private_key,
            value,
            blinding,
            output_blinding,
            generator,
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
    // * `ring` - A ring of reduced TxOuts
    // * `real_index` - The index in the ring of the real input.
    // * `onetime_private_key` - The real input's private key.
    // * `value` - Value of the real input.
    // * `blinding` - Blinding of the real input.
    // * `output_blinding` - The output amount's blinding factor.
    // * `generator` - The pedersen generator to use for this commitment and
    //   signature
    // * `check_value_is_preserved` - If true, check that the value of inputs equals
    //   value of outputs.
    // * `rng` - Randomness.
    #[allow(unreachable_code, unused_variables)]
    fn sign_with_balance_check(
        message: &[u8],
        ring: &[ReducedTxOut],
        real_index: usize,
        onetime_private_key: &RistrettoPrivate,
        value: u64,
        blinding: &Scalar,
        output_blinding: &Scalar,
        generator: &PedersenGens,
        check_value_is_preserved: bool,
        // Note: this `mut rng` can just be `rng` if this is merged upstream:
        // https://github.com/dalek-cryptography/curve25519-dalek/pull/394
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Self, Error> {
        let ring_size = ring.len();

        // Setup buffers
        let (mut responses, mut decompressed_ring) = (
            alloc::vec![CurveScalar::from(Scalar::zero()); 2 * ring_size],
            alloc::vec![(RistrettoPublic::default(), Commitment::default()); ring_size],
        );

        // Pre-decompress ring
        for (i, r) in ring.iter().enumerate() {
            decompressed_ring[i] = r.try_into()?;
        }

        // Setup and call signer
        let opts = MlsagSignParams {
            ring_size,
            message,
            real_index,
            onetime_private_key,
            value,
            blinding,
            output_blinding,
            generator,
            check_value_is_preserved,
        };
        let (key_image, c_zero) = opts.sign(&decompressed_ring[..], rng, &mut responses)?;

        // Build MLSAG output
        let res = RingMLSAG {
            c_zero,
            responses,
            key_image,
        };

        // Zeroize buffers
        decompressed_ring.iter_mut().for_each(|(p, _c)| p.zeroize());

        Ok(res)
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
        ring: &[ReducedTxOut],
        output_commitment: &CompressedCommitment,
    ) -> Result<(), Error> {
        let ring_size = ring.len();

        // Setup buffers for recomputed_c and decompressed rings
        let (mut recomputed_c, mut decompressed_ring) = (
            alloc::vec![Scalar::zero(); ring_size],
            alloc::vec![(RistrettoPublic::default(), Commitment::default()); ring_size],
        );

        // Pre-decompress ring
        for (i, r) in ring.iter().enumerate() {
            decompressed_ring[i] = r.try_into()?;
        }

        // Setup and execute verification
        let opts = MlsagVerify {
            key_image: &self.key_image,
            c_zero: &self.c_zero,
            responses: &self.responses,
            message,
            ring: &decompressed_ring[..],
            output_commitment,
        };

        // Execute verification
        let res = opts.verify(&mut recomputed_c);

        // Zeroize buffers
        recomputed_c.iter_mut().for_each(|v| v.zeroize());
        decompressed_ring.iter_mut().for_each(|(p, _c)| p.zeroize());

        res
    }
}

#[cfg(test)]
mod mlsag_tests {
    use super::*;
    use crate::generators;
    use curve25519_dalek::ristretto::CompressedRistretto;
    use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
    use mc_util_from_random::FromRandom;
    use mc_util_test_helper::{RngCore, RngType, SeedableRng};
    use proptest::prelude::*;

    use alloc::vec::Vec;
    #[derive(Clone)]
    struct RingMLSAGParameters {
        message: [u8; 32],
        ring: Vec<ReducedTxOut>,
        real_index: usize,
        onetime_private_key: RistrettoPrivate,
        value: u64,
        blinding: Scalar,
        pseudo_output_blinding: Scalar,
        generator: PedersenGens,
    }

    impl RingMLSAGParameters {
        fn random<RNG: CryptoRngCore>(
            num_mixins: usize,
            pseudo_output_blinding: Scalar,
            rng: &mut RNG,
        ) -> Self {
            let mut message = [0u8; 32];
            rng.fill_bytes(&mut message);

            let generator = generators(rng.next_u64());

            let mut ring: Vec<ReducedTxOut> = Vec::new();
            for _i in 0..num_mixins {
                let public_key = CompressedRistrettoPublic::from_random(rng);
                let target_key = CompressedRistrettoPublic::from_random(rng);
                let commitment = {
                    let value = rng.next_u64();
                    let blinding = Scalar::random(rng);
                    CompressedCommitment::new(value, blinding, &generator)
                };
                let _ = ring.push(ReducedTxOut {
                    public_key,
                    target_key,
                    commitment,
                });
            }

            // The real input.
            let onetime_private_key = RistrettoPrivate::from_random(rng);

            let value = rng.next_u64();
            let blinding = Scalar::random(rng);
            let commitment = CompressedCommitment::new(value, blinding, &generator);

            let reduced_tx_out = ReducedTxOut {
                target_key: CompressedRistrettoPublic::from(RistrettoPublic::from(
                    &onetime_private_key,
                )),
                public_key: CompressedRistrettoPublic::from_random(rng),
                commitment,
            };

            let real_index = rng.next_u64() as usize % (num_mixins + 1);
            let _ = ring.insert(real_index, reduced_tx_out);
            assert_eq!(ring.len(), num_mixins + 1);

            Self {
                message,
                ring,
                real_index,
                onetime_private_key,
                value,
                blinding,
                pseudo_output_blinding,
                generator,
            }
        }

        fn sign<RNG: CryptoRngCore>(&self, rng: &mut RNG) -> Result<RingMLSAG, Error> {
            RingMLSAG::sign(
                &self.message,
                &self.ring,
                self.real_index,
                &self.onetime_private_key,
                self.value,
                &self.blinding,
                &self.pseudo_output_blinding,
                &self.generator,
                rng,
            )
        }

        fn sign_without_balance_check<RNG: CryptoRngCore>(
            &self,
            rng: &mut RNG,
        ) -> Result<RingMLSAG, Error> {
            RingMLSAG::sign_with_balance_check(
                &self.message,
                &self.ring,
                self.real_index,
                &self.onetime_private_key,
                self.value,
                &self.blinding,
                &self.pseudo_output_blinding,
                &self.generator,
                false,
                rng,
            )
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(6))]

        #[test]
        // `sign` should return a signature with 2*ring_size responses.
        fn test_signature_responses_has_correct_length(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: RngType = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);

            let params =
                RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = params.sign(&mut rng).unwrap();

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
            let mut rng: RngType = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = params.sign(&mut rng).unwrap();

            let expected_key_image = KeyImage::from(&params.onetime_private_key);
            assert_eq!(signature.key_image, expected_key_image);
        }

        #[test]
        // `sign` should return an Error if the input and output have different values.
        fn test_sign_returns_error_if_value_is_not_conserved(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: RngType = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let mut params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);
            let wrong_value = rng.next_u64();
            params.value = wrong_value;

            let result = params.sign(&mut rng);

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
            let mut rng: RngType = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let mut params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);
            // The ring contains num_mixins + 1 elements, with indices 0..num_mixins.
            // This is the smallest out of bounds index.
            let wrong_real_index = num_mixins + 1;

            params.real_index = wrong_real_index;

            let result = params.sign(&mut rng);

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
            let mut rng: RngType = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = params.sign(&mut rng).unwrap();

            let output_commitment = CompressedCommitment::new(params.value, params.pseudo_output_blinding, &params.generator);

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
            let mut rng: RngType = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let mut params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);
            let wrong_onetime_private_key = RistrettoPrivate::from_random(&mut rng);
            params.onetime_private_key = wrong_onetime_private_key;

            let signature = params.sign(&mut rng).unwrap();

            let output_commitment = CompressedCommitment::new(params.value, params.pseudo_output_blinding, &params.generator);

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
            let mut rng: RngType = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            // Sign with an input value that differs from the real input's amount commitment.
            {
                let mut params = params.clone();
                let wrong_value = rng.next_u64();
                params.value = wrong_value;
                // Disable value checking in order to create an invalid signature.
                let invalid_signature = params.sign_without_balance_check(&mut rng).unwrap();

                let output_commitment = CompressedCommitment::new(wrong_value, params.pseudo_output_blinding, &params.generator);

                let result =
                    invalid_signature.verify(&params.message, &params.ring, &output_commitment);

                match result {
                    Err(Error::InvalidSignature) => {} // This is expected.
                    _ => panic!(),
                }
            }

            // Sign with an input blinding that differs from the real input's amount commitment.
            {
                let mut params = params;
                let wrong_blinding = Scalar::random(&mut rng);

                params.blinding = wrong_blinding;

                // Disable value checking in order to create an invalid signature.
                let invalid_signature = params.sign_without_balance_check(&mut rng).unwrap();

                let output_commitment = CompressedCommitment::new(params.value, wrong_blinding, &params.generator);

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
            let mut rng: RngType = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let mut signature = params.sign(&mut rng).unwrap();

            // Replace the key image with a non-canonical compressed Ristretto point.
            // This is constants::EDWARDS_D.to_bytes(), which is a negative point, so decompression should fail.
            // Edwards `d` value, equal to `-121665/121666 mod p`.
            let edwards_d : [u8; 32] = [163, 120, 89, 19, 202, 77, 235, 117, 171, 216, 65, 65, 77, 10, 112, 0, 152, 232, 121, 119, 121, 64, 199, 140, 115, 254, 111, 43, 238, 108, 3, 82];
            let bad_compressed = CompressedRistretto(edwards_d);
            assert!(bad_compressed.decompress().is_none());

            signature.key_image = KeyImage{point: bad_compressed};

            let output_commitment = CompressedCommitment::new(params.value, params.pseudo_output_blinding, &params.generator);

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
            let mut rng: RngType = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let mut signature = params.sign(&mut rng).unwrap();

            // Modify the key image.
            let wrong_key_image = KeyImage::from(rng.next_u64());
            signature.key_image = wrong_key_image;

            let output_commitment = CompressedCommitment::new(params.value, params.pseudo_output_blinding, &params.generator);

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
            let mut rng: RngType = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = params.sign(&mut rng).unwrap();

            // Modify the message.
            let mut wrong_message = [0u8; 32];
            rng.fill_bytes(&mut wrong_message);

            let output_commitment = CompressedCommitment::new(params.value, params.pseudo_output_blinding, &params.generator);

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
            let mut rng: RngType = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let mut params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = params.sign(&mut rng).unwrap();

            let output_commitment = CompressedCommitment::new(params.value, params.pseudo_output_blinding, &params.generator);

            // Modify a ring element's target key.
            {
                let index = (rng.next_u64() as usize) % num_mixins;
                params.ring[index].target_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));

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
                params.ring[index].commitment = CompressedCommitment::new(value, blinding, &params.generator);

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
           let mut rng: RngType = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = params.sign(&mut rng).unwrap();

            // The output_commitment should match the value and pseudo_output_blinding used by the signature.
            // Here, the output_commitment uses a different value.
            let wrong_output_commitment = CompressedCommitment::new(rng.next_u64(), params.pseudo_output_blinding, &params.generator);

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
            let mut rng: RngType = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);

            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = params.sign(&mut rng).unwrap();

            let output_commitment = CompressedCommitment::new(params.value, params.pseudo_output_blinding, &params.generator);

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
                let mut invalid_signature = signature;
                let _ = invalid_signature.responses.push(CurveScalar::from_random(&mut rng));

                let result =
                    invalid_signature.verify(&params.message, &params.ring, &output_commitment);

                match result {
                    Err(Error::LengthMismatch(_, _)) => {} // This is expected.
                    _ => panic!(),
                }
            }
        }

        #[test]
        #[cfg(feature = "prost")]
        // decode(encode(&signature)) should be the identity function.
        fn test_encode_decode(
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: RngType = SeedableRng::from_seed(seed);
            let pseudo_output_blinding = Scalar::random(&mut rng);
            let params = RingMLSAGParameters::random(num_mixins, pseudo_output_blinding, &mut rng);

            let signature = params.sign(&mut rng).unwrap();

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
