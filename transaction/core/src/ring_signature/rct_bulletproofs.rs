// Copyright (c) 2018-2021 The MobileCoin Foundation

//! An RCT_TYPE_BULLETPROOFS_2 signature.
//!
//! # References
//! * [Ring Confidential Transactions](https://eprint.iacr.org/2015/1098.pdf)
//! * [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf)

extern crate alloc;

use alloc::vec::Vec;
use bulletproofs::RangeProof;
use core::convert::TryFrom;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use mc_common::HashSet;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate};
use mc_util_serial::prost::Message;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    constants::FEE_BLINDING,
    range_proofs::{check_range_proofs, generate_range_proofs},
    ring_signature::{mlsag::RingMLSAG, Error, KeyImage, Scalar, GENERATORS},
    Commitment, CompressedCommitment,
};

/// An RCT_TYPE_BULLETPROOFS_2 signature.
#[derive(Clone, Digestible, Eq, PartialEq, Serialize, Deserialize, Message)]
pub struct SignatureRctBulletproofs {
    /// Signature for each input ring.
    #[prost(message, repeated, tag = "1")]
    pub ring_signatures: Vec<RingMLSAG>,

    /// Commitments of value equal to each real input.
    #[prost(message, repeated, tag = "2")]
    pub pseudo_output_commitments: Vec<CompressedCommitment>,

    /// Proof that all pseudo_outputs and transaction outputs are in [0, 2^64).
    /// This contains range_proof.to_bytes(). It is stored this way so that this
    /// struct may derive Default, which is a requirement for serializing
    /// with Prost.
    #[prost(bytes, tag = "3")]
    pub range_proof_bytes: Vec<u8>,
}

impl SignatureRctBulletproofs {
    /// Sign.
    ///
    /// # Arguments
    /// * `message` - The messages to be signed, e.g. Hash(TxPrefix).
    /// * `rings` - One or more rings of one-time addresses and amount
    ///   commitments.
    /// * `real_input_indices` - The index of the real input in each ring.
    /// * `input_secrets` - One-time private key, amount value, and amount
    ///   blinding for each real input.
    /// * `output_values_and_blindings` - Value and blinding for each output
    ///   amount commitment.
    /// * `fee` - Value of the implicit fee output.
    pub fn sign<CSPRNG: RngCore + CryptoRng>(
        message: &[u8; 32],
        rings: &[Vec<(CompressedRistrettoPublic, CompressedCommitment)>],
        real_input_indices: &[usize],
        input_secrets: &[(RistrettoPrivate, u64, Scalar)],
        output_values_and_blindings: &[(u64, Scalar)],
        fee: u64,
        rng: &mut CSPRNG,
    ) -> Result<Self, Error> {
        sign_with_balance_check(
            message,
            rings,
            real_input_indices,
            input_secrets,
            output_values_and_blindings,
            fee,
            true,
            rng,
        )
    }

    /// Verify.
    ///
    /// # Arguments
    /// * `message` - The signed message.
    /// * `rings` - One or more rings of one-time addresses and amount
    ///   commitments.
    /// * `output_commitments` - Output amount commitments.
    /// * `fee` - Value of the implicit fee output.
    /// * `rng` -
    pub fn verify<CSPRNG: RngCore + CryptoRng>(
        &self,
        message: &[u8; 32],
        rings: &[Vec<(CompressedRistrettoPublic, CompressedCommitment)>],
        output_commitments: &[CompressedCommitment],
        fee: u64,
        rng: &mut CSPRNG,
    ) -> Result<(), Error> {
        // Signature must contain one ring signature for each ring.
        if rings.len() != self.ring_signatures.len() {
            return Err(Error::LengthMismatch(
                rings.len(),
                self.ring_signatures.len(),
            ));
        }

        // Signature must contain one pseudo_output for each ring.
        if rings.len() != self.pseudo_output_commitments.len() {
            return Err(Error::LengthMismatch(
                rings.len(),
                self.pseudo_output_commitments.len(),
            ));
        }

        // Key images must be unique.
        {
            let key_images_are_unique = {
                let mut uniq = HashSet::default();
                self.key_images().into_iter().all(move |x| uniq.insert(x))
            };
            if !key_images_are_unique {
                return Err(Error::DuplicateKeyImage);
            }
        }

        // output_commitments must decompress.
        // This ensures that each commitment encodes a valid Ristretto point.
        let mut decompressed_output_commitments: Vec<Commitment> = Vec::new();
        for output_commitment in output_commitments {
            let commitment = Commitment::try_from(output_commitment)?;
            decompressed_output_commitments.push(commitment);
        }

        // pseudo_output_commitments must decompress.
        // This ensures that each commitment encodes a valid Ristretto point.
        let mut decompressed_pseudo_output_commitments: Vec<Commitment> = Vec::new();
        for pseudo_output in &self.pseudo_output_commitments {
            let commitment = Commitment::try_from(pseudo_output)?;
            decompressed_pseudo_output_commitments.push(commitment);
        }

        // pseudo_output_commitments and output commitments must be in [0, 2^64).
        {
            let commitments: Vec<CompressedRistretto> = self
                .pseudo_output_commitments
                .iter()
                .chain(output_commitments.iter())
                .map(|compressed_commitment| compressed_commitment.point)
                .collect();

            let range_proof = RangeProof::from_bytes(&self.range_proof_bytes)
                .map_err(|_e| Error::RangeProofError)?;

            check_range_proofs(&range_proof, &commitments, rng)
                .map_err(|_e| Error::RangeProofError)?;
        }

        // Output commitments - pseudo_outputs must be zero.
        {
            let sum_of_output_commitments: RistrettoPoint = decompressed_output_commitments
                .iter()
                .map(|commitment| commitment.point)
                .sum();

            let sum_of_pseudo_output_commitments: RistrettoPoint =
                decompressed_pseudo_output_commitments
                    .iter()
                    .map(|commitment| commitment.point)
                    .sum();

            // The implicit fee output.
            let fee_commitment = GENERATORS.commit(Scalar::from(fee), *FEE_BLINDING);
            let difference =
                sum_of_output_commitments + fee_commitment - sum_of_pseudo_output_commitments;
            if difference != GENERATORS.commit(Scalar::zero(), Scalar::zero()) {
                return Err(Error::ValueNotConserved);
            }
        }

        // Extend the message with the range proof and pseudo_output_commitments.
        let extended_message = extend_message(
            message,
            &self.pseudo_output_commitments,
            &self.range_proof_bytes,
        );

        // Each MLSAG must be valid.
        for (i, ring) in rings.iter().enumerate() {
            let ring_signature = &self.ring_signatures[i];
            let pseudo_output = self.pseudo_output_commitments[i];
            ring_signature.verify(&extended_message, ring, &pseudo_output)?;
        }

        // Signature is valid.
        Ok(())
    }

    /// Key images spent by this signature.
    pub fn key_images(&self) -> Vec<KeyImage> {
        self.ring_signatures
            .iter()
            .map(|mlsag| mlsag.key_image)
            .collect()
    }
}

/// Sign, with optional check for inputs = outputs.
///
/// # Arguments
/// * `message` - The messages to be signed, e.g. Hash(TxPrefix).
/// * `rings` - One or more rings of one-time addresses and amount commitments.
/// * `real_input_indices` - The index of the real input in each ring.
/// * `input_secrets` - One-time private key, amount value, and amount blinding
///   for each real input.
/// * `output_values_and_blindings` - Value and blinding for each output amount
///   commitment.
/// * `fee` - Value of the implicit fee output.
/// * `check_value_is_preserved` - If true, check that the value of inputs
///   equals value of outputs.
fn sign_with_balance_check<CSPRNG: RngCore + CryptoRng>(
    message: &[u8; 32],
    rings: &[Vec<(CompressedRistrettoPublic, CompressedCommitment)>],
    real_input_indices: &[usize],
    input_secrets: &[(RistrettoPrivate, u64, Scalar)],
    output_values_and_blindings: &[(u64, Scalar)],
    fee: u64,
    check_value_is_preserved: bool,
    rng: &mut CSPRNG,
) -> Result<SignatureRctBulletproofs, Error> {
    if rings.is_empty() {
        return Err(Error::NoInputs);
    }
    let num_inputs = rings.len();
    let ring_size = rings[0].len();
    if ring_size == 0 {
        return Err(Error::InvalidRingSize(0));
    }

    // Each ring must have the same size.
    for ring in rings {
        if ring.len() != ring_size {
            return Err(Error::InvalidRingSize(ring.len()));
        }
    }

    // `input_secrets` must contain an element for each input.
    if input_secrets.len() != num_inputs {
        return Err(Error::InvalidInputSecretsSize(input_secrets.len()));
    }

    // Each `real_input_index` must be in [0,ring_size - 1].
    for i in real_input_indices {
        if *i >= ring_size {
            return Err(Error::IndexOutOfBounds);
        }
    }

    // Blindings for pseudo_outputs. All but the last are random.
    // Constructing blindings in this way ensures that sum_of_outputs -
    // sum_of_pseudo_outputs = 0 if the sum of outputs and the sum of
    // pseudo_outputs have equal value.
    let mut pseudo_output_blindings: Vec<Scalar> = Vec::new();
    for _i in 0..num_inputs - 1 {
        pseudo_output_blindings.push(Scalar::random(rng));
    }
    // The implicit fee output is ommitted because its blinding is zero.
    let sum_of_output_blindings: Scalar = output_values_and_blindings
        .iter()
        .map(|(_, blinding)| blinding)
        .sum();

    let sum_of_pseudo_output_blindings: Scalar = pseudo_output_blindings.iter().sum();
    let last_blinding: Scalar = sum_of_output_blindings - sum_of_pseudo_output_blindings;
    pseudo_output_blindings.push(last_blinding);

    // Create Range proofs for outputs and pseudo-outputs.
    let pseudo_output_values_and_blindings: Vec<(u64, Scalar)> = input_secrets
        .iter()
        .zip(pseudo_output_blindings.iter())
        .map(|((_, value, _), blinding)| (*value, *blinding))
        .collect();

    let (range_proof, commitments) = {
        let values_and_blindings: Vec<(u64, Scalar)> = pseudo_output_values_and_blindings
            .iter()
            .chain(output_values_and_blindings.iter())
            .map(|(value, blinding)| (*value, *blinding))
            .collect();

        // The implicit fee output is omitted from the range proof because it is known.

        let (values, blindings): (Vec<_>, Vec<_>) = values_and_blindings.into_iter().unzip();
        generate_range_proofs(&values, &blindings, rng).map_err(|_e| Error::RangeProofError)?
    };

    if check_value_is_preserved {
        let sum_of_output_commitments: RistrettoPoint = output_values_and_blindings
            .iter()
            .map(|(value, blinding)| GENERATORS.commit(Scalar::from(*value), *blinding))
            .sum();

        let sum_of_pseudo_output_commitments: RistrettoPoint = pseudo_output_values_and_blindings
            .iter()
            .map(|(value, blinding)| GENERATORS.commit(Scalar::from(*value), *blinding))
            .sum();

        // The implicit fee output.
        let fee_commitment = GENERATORS.commit(Scalar::from(fee), *FEE_BLINDING);

        let difference =
            sum_of_output_commitments + fee_commitment - sum_of_pseudo_output_commitments;
        if difference != GENERATORS.commit(Scalar::zero(), Scalar::zero()) {
            return Err(Error::ValueNotConserved);
        }
    }

    let pseudo_output_commitments: Vec<CompressedCommitment> = commitments
        .iter()
        .take(num_inputs)
        .map(CompressedCommitment::from)
        .collect();

    // Extend the message with the range proof and pseudo_output_commitments.
    // This ensures that they are signed by each RingMLSAG.
    let range_proof_bytes = range_proof.to_bytes();
    let extended_message = extend_message(message, &pseudo_output_commitments, &range_proof_bytes);

    // Prove that the signer is allowed to spend a public key in each ring, and that
    // the input's value equals the value of the pseudo_output.
    let mut ring_signatures: Vec<RingMLSAG> = Vec::new();
    for i in 0..num_inputs {
        let real_index = real_input_indices[i];
        let (onetime_private_key, value, blinding) = input_secrets[i];
        let ring_signature = RingMLSAG::sign(
            &extended_message,
            &rings[i],
            real_index,
            &onetime_private_key,
            value,
            &blinding,
            &pseudo_output_blindings[i],
            rng,
        )?;
        ring_signatures.push(ring_signature);
    }

    Ok(SignatureRctBulletproofs {
        ring_signatures,
        pseudo_output_commitments,
        range_proof_bytes,
    })
}

/// Concatenates [message || pseudo_output_commitments || range_proof].
fn extend_message(
    message: &[u8],
    pseudo_output_commitments: &[CompressedCommitment],
    range_proof_bytes: &[u8],
) -> Vec<u8> {
    let mut extended_message: Vec<u8> = Vec::with_capacity(
        message.len() + pseudo_output_commitments.len() * 32 + range_proof_bytes.len(),
    );
    extended_message.extend_from_slice(message);
    for commitment in pseudo_output_commitments {
        extended_message.extend_from_slice(commitment.as_ref());
    }
    extended_message.extend_from_slice(&range_proof_bytes);
    extended_message
}

#[cfg(test)]
mod rct_bulletproofs_tests {
    use super::sign_with_balance_check;
    use crate::{
        range_proofs::generate_range_proofs,
        ring_signature::{Error, KeyImage, SignatureRctBulletproofs},
        CompressedCommitment,
    };
    use alloc::vec::Vec;
    use curve25519_dalek::scalar::Scalar;
    use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
    use mc_util_from_random::FromRandom;
    use proptest::prelude::*;
    use rand::{rngs::StdRng, CryptoRng, SeedableRng};
    use rand_core::RngCore;

    extern crate std;

    struct SignatureParams {
        /// Message to be signed.
        message: [u8; 32],

        /// Rings of input onetime addresses and amount commitments.
        rings: Vec<Vec<(CompressedRistrettoPublic, CompressedCommitment)>>,

        /// The index of the real input in each ring.
        real_input_indices: Vec<usize>,

        /// One-time private key, amount value, and amount blinding for each
        /// real input.
        input_secrets: Vec<(RistrettoPrivate, u64, Scalar)>,

        /// Value and blinding for each output amount commitment.
        output_values_and_blindings: Vec<(u64, Scalar)>,
    }

    impl SignatureParams {
        fn random<RNG: RngCore + CryptoRng>(
            num_inputs: usize,
            num_mixins: usize,
            rng: &mut RNG,
        ) -> Self {
            let mut message = [0u8; 32];
            rng.fill_bytes(&mut message);

            let mut rings = Vec::new();
            let mut real_input_indices = Vec::new();
            let mut input_secrets = Vec::new();

            for _i in 0..num_inputs {
                let mut ring: Vec<(CompressedRistrettoPublic, CompressedCommitment)> = Vec::new();
                // Create random mixins.
                for _i in 0..num_mixins {
                    let address =
                        CompressedRistrettoPublic::from(RistrettoPublic::from_random(rng));
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

                rings.push(ring);
                real_input_indices.push(real_index);
                input_secrets.push((onetime_private_key, value, blinding));
            }

            // Create one output with the same value as each input.
            let output_values_and_blindings: Vec<_> = input_secrets
                .iter()
                .map(|(_, value, _)| {
                    let blinding = Scalar::random(rng);
                    (*value, blinding)
                })
                .collect();

            SignatureParams {
                message,
                rings,
                real_input_indices,
                input_secrets,
                output_values_and_blindings,
            }
        }

        fn get_output_commitments(&self) -> Vec<CompressedCommitment> {
            self.output_values_and_blindings
                .iter()
                .map(|(value, blinding)| CompressedCommitment::new(*value, *blinding))
                .collect()
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(3))]

        #[test]
        // `sign`should return an error if `rings` is empty.
        fn sign_rejects_empty_rings(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let mut params = SignatureParams::random(num_inputs, num_mixins, &mut rng);
            params.rings = Vec::new();

            let result = SignatureRctBulletproofs::sign(
                &params.message,
                &params.rings,
                &params.real_input_indices,
                &params.input_secrets,
                &params.output_values_and_blindings,
                0,
                &mut rng,
            );

            match result {
                Err(Error::NoInputs) => {} // OK,
                _ => panic!(),
            }
        }

        #[test]
        // `sign`should return an error if `rings[0]` is empty.
        // The first ring is used to infer the ring size.
        fn sign_rejects_empty_rings_zero(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let mut params = SignatureParams::random(num_inputs, num_mixins, &mut rng);
            params.rings[0] = Vec::new();

            let result = SignatureRctBulletproofs::sign(
                &params.message,
                &params.rings,
                &params.real_input_indices,
                &params.input_secrets,
                &params.output_values_and_blindings,
                0,
                &mut rng,
            );

            match result {
                Err(Error::InvalidRingSize(0)) => {} // OK,
                _ => panic!(),
            }
        }

        #[test]
        // `sign` should produce a signature with one ring signature and one pseudo-output per input.
        fn sign_signature_has_correct_lengths(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let params = SignatureParams::random(num_inputs, num_mixins, &mut rng);
            let signature = SignatureRctBulletproofs::sign(
                &params.message,
                &params.rings,
                &params.real_input_indices,
                &params.input_secrets,
                &params.output_values_and_blindings,
                0,
                &mut rng,
            )
            .unwrap();

            // The signature must contain one ring signature per input.
            assert_eq!(signature.ring_signatures.len(), num_inputs);

            // The signature must contain one pseudo-output per input.
            assert_eq!(signature.pseudo_output_commitments.len(), num_inputs);

            let ring_size = num_mixins + 1;
            for ring_signature in &signature.ring_signatures {
                assert_eq!(ring_signature.responses.len(), 2 * ring_size);
            }
        }

        #[test]
        // `verify` should accept valid signatures.
        fn verify_accepts_valid_signatures(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let params = SignatureParams::random(num_inputs, num_mixins, &mut rng);
            let fee = 0;
            let signature = SignatureRctBulletproofs::sign(
                &params.message,
                &params.rings,
                &params.real_input_indices,
                &params.input_secrets,
                &params.output_values_and_blindings,
                fee,
                &mut rng,
            )
            .unwrap();

            let result = signature.verify(
                &params.message,
                &params.rings,
                &params.get_output_commitments(),
                fee,
                &mut rng,
            );
            assert!(result.is_ok());
        }

        #[test]
        // `verify` should reject a signature that contains an invalid MLSAG signature.
        fn test_verify_rejects_signature_signed_with_invalid_mlsag(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let params = SignatureParams::random(num_inputs, num_mixins, &mut rng);
            let fee = 0;
            let mut signature = SignatureRctBulletproofs::sign(
                &params.message,
                &params.rings,
                &params.real_input_indices,
                &params.input_secrets,
                &params.output_values_and_blindings,
                fee,
                &mut rng,
            )
            .unwrap();

            // Modify an MLSAG ring signature
            let index = rng.next_u64() as usize % (num_inputs);
            signature.ring_signatures[index].key_image = KeyImage::from(rng.next_u64());

            let result = signature.verify(
                &params.message,
                &params.rings,
                &params.get_output_commitments(),
                fee,
                &mut rng,
            );

            assert_eq!(result, Err(Error::InvalidSignature));
        }

        #[test]
        // `verify` rejects a signature if the sum of the outputs minus the sum of the pseudo-outputs is not zero.
        fn test_verify_rejects_signature_when_value_not_conserved(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let mut params = SignatureParams::random(num_inputs, num_mixins, &mut rng);
            let fee = 0;
            // Modify an output value
            {
                let index = rng.next_u64() as usize % (num_inputs);
                let (_value, blinding) = params.output_values_and_blindings[index].clone();
                params.output_values_and_blindings[index] = (rng.next_u64(), blinding);
            }

            // Sign, without checking that value is preserved.
            let invalid_signature = sign_with_balance_check(
                &params.message,
                &params.rings,
                &params.real_input_indices,
                &params.input_secrets,
                &params.output_values_and_blindings,
                fee,
                false,
                &mut rng,
            )
            .unwrap();

            let result = invalid_signature.verify(
                &params.message,
                &params.rings,
                &params.get_output_commitments(),
                fee,
                &mut rng,
            );

            assert_eq!(result, Err(Error::ValueNotConserved));
        }

        #[test]
        // `verify` rejects a signature with invalid range proof.
        fn test_verify_rejects_signature_with_invalid_range_proof(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let params = SignatureParams::random(num_inputs, num_mixins, &mut rng);
            let fee = 0;
            let mut signature = SignatureRctBulletproofs::sign(
                &params.message,
                &params.rings,
                &params.real_input_indices,
                &params.input_secrets,
                &params.output_values_and_blindings,
                fee,
                &mut rng,
            )
            .unwrap();

            // Modify the range proof
            let wrong_range_proof = {
                let values = [13; 6];
                let blindings: Vec<Scalar> = values
                    .iter()
                    .map(|_value| Scalar::random(&mut rng))
                    .collect();
                let (range_proof, _commitments) =
                    generate_range_proofs(&values, &blindings, &mut rng).unwrap();
                range_proof
            };

            signature.range_proof_bytes = wrong_range_proof.to_bytes();

            let result = signature.verify(
                &params.message,
                &params.rings,
                &params.get_output_commitments(),
                fee,
                &mut rng,
            );

            assert_eq!(result, Err(Error::RangeProofError));
        }

        #[test]
        // `verify` rejects a signature that spends the same input in two different rings.
        fn test_verify_rejects_signature_with_duplicate_key_images(
            num_inputs in 4..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let mut params = SignatureParams::random(num_inputs, num_mixins, &mut rng);
            let fee = 0;

            // Duplicate one of the rings.
            params.rings[2] = params.rings[3].clone();
            params.output_values_and_blindings[2] = params.output_values_and_blindings[3].clone();
            params.input_secrets[2] = params.input_secrets[3].clone();
            params.real_input_indices[2] = params.real_input_indices[3];

            let signature = SignatureRctBulletproofs::sign(
                &params.message,
                &params.rings,
                &params.real_input_indices,
                &params.input_secrets,
                &params.output_values_and_blindings,
                fee,
                &mut rng,
            )
            .unwrap();

            let result = signature.verify(
                &params.message,
                &params.rings,
                &params.get_output_commitments(),
                fee,
                &mut rng,
            );

            assert_eq!(result, Err(Error::DuplicateKeyImage));
        }

        #[test]
        // decode(encode(&signature)) should be the identity function.
        fn test_encode_decode(
            num_inputs in 4..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let params = SignatureParams::random(num_inputs, num_mixins, &mut rng);
            let fee = 0;
            let signature = SignatureRctBulletproofs::sign(
                &params.message,
                &params.rings,
                &params.real_input_indices,
                &params.input_secrets,
                &params.output_values_and_blindings,
                fee,
                &mut rng,
            )
            .unwrap();

            use mc_util_serial::prost::Message;

            // The encoded bytes should have the correct length.
            let bytes = mc_util_serial::encode(&signature);
            assert_eq!(bytes.len(), signature.encoded_len());

            // decode(encode(&signature)) should be the identity function.
            let recovered_signature : SignatureRctBulletproofs = mc_util_serial::decode(&bytes).unwrap();
            assert_eq!(signature, recovered_signature);
        }

        // `verify` should accept valid signatures with correct fee.
        fn verify_with_fee(
            num_inputs in 2..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let mut params = SignatureParams::random(num_inputs, num_mixins, &mut rng);
            // Remove one of the outputs, and use its value as the fee. This conserves value.
            let (fee, _) = params.output_values_and_blindings.pop().unwrap();

            let signature = SignatureRctBulletproofs::sign(
                &params.message,
                &params.rings,
                &params.real_input_indices,
                &params.input_secrets,
                &params.output_values_and_blindings,
                fee,
                &mut rng,
            )
            .unwrap();


            let result = signature.verify(
                &params.message,
                &params.rings,
                &params.get_output_commitments(),
                fee,
                &mut rng,
            );
            assert!(result.is_ok());

            // Verify should fail if the signature disagrees with the fee.
            let wrong_fee = fee + 1;
            match signature.verify(
                &params.message,
                &params.rings,
                &params.get_output_commitments(),
                wrong_fee,
                &mut rng,
            ) {
                Err(Error::ValueNotConserved) => {} // Expected
                Err(e) => {
                    panic!("Unexpected error {}", e);
                }
                _ => panic!("Unexpected success")
            }

        }

    } // end proptest
}
