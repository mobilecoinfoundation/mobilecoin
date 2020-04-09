// Copyright (c) 2018-2020 MobileCoin Inc.

//! An RCTTypeFull signature with bulletproofs.
//!
//! # Variable names:
//! * `I` for key images,
//! * `c` for the challenges,
//! * `x` for public keys,
//! * `y` for the public keys (`P[i,k]` in the paper),
//! * `r` for challenge responses (`s[i,k]` in the paper),
//!
//! # References
//! * [Ring Confidential Transactions](https://eprint.iacr.org/2015/1098.pdf)
//! * [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf)

#![allow(clippy::many_single_char_names, clippy::needless_range_loop)]

extern crate alloc;
use crate::{onetime_keys::compute_key_image_uncompressed, ring_signature::*};
use alloc::{vec, vec::Vec};
use blake2::{Blake2b, Digest};
use core::{
    convert::{AsRef, From},
    default::Default,
};
use curve25519_dalek::ristretto::RistrettoPoint;
pub use curve25519_dalek::scalar::Scalar;
use digestible::Digestible;
use keys::RistrettoPrivate;
use mcserial::ReprBytes32;
use prost::Message;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// An RCTTypeFull signature.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Message, Digestible)]
pub struct SignatureRctFull {
    /// Key images `I_1, ... I_m` "spent" by this signature.
    #[prost(message, repeated, tag = "1")]
    pub key_images: Vec<KeyImage>,

    /// The set of `s_i^j` terms in the ring signature.
    #[prost(message, repeated, tag = "2")]
    pub challenge_responses: Vec<ChallengeResponse>,

    /// The initial `c_1` term in the ring signature.
    #[prost(message, required, tag = "3")]
    pub challenge: CurveScalar,
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Message, Digestible)]
pub struct ChallengeResponse {
    #[prost(message, repeated, tag = "1")]
    pub response: Vec<CurveScalar>,
}

impl From<Vec<CurveScalar>> for ChallengeResponse {
    #[inline]
    fn from(response: Vec<CurveScalar>) -> Self {
        Self { response }
    }
}

/// Generates a RingCT signature.
///
/// # Arguments
/// `prefix_hash` - Hash of a transaction prefix.
/// `input_rows` - Input addresses and commitments; one row (`real_input_row`) belongs to signer.
/// `out_commitments_and_blindings` - Output commitments with blindings.
/// `input_keys_and_blindings` - `in_secrets` - Input onetime private keys and blindings.
/// `real_input_row` - Row in the `input_rows` matrix owned by the signer.
/// `csprng` - Randomness.
pub fn sign<RNG: RngCore + CryptoRng>(
    prefix_hash: &[u8; 32],
    input_rows: &[Vec<(Address, Commitment)>],
    output_commitments_and_blindings: &[(Commitment, Blinding)],
    input_keys_and_blindings: &[(RistrettoPrivate, Blinding)],
    real_input_row: usize,
    csprng: &mut RNG,
) -> Result<SignatureRctFull, Error> {
    sign_with_value_check(
        prefix_hash,
        input_rows,
        output_commitments_and_blindings,
        input_keys_and_blindings,
        real_input_row,
        true,
        csprng,
    )
}

/// Generates a RingCT signature, with optional check for inputs = outputs.
///
/// This function exists to facilitate unit testing.
///
/// # Arguments
/// `prefix_hash` - Hash of a transaction prefix.
/// `input_rows` - Input addresses and commitments; one row (`real_input_row`) belongs to signer.
/// `out_commitments_and_blindings` - Output commitments with blindings.
/// `input_keys_and_blindings` - `in_secrets` - Input onetime private keys and blindings.
/// `real_input_row` - Row in the `input_rows` matrix owned by the signer.
/// `check_value_is_preserved` - If true, check that the value of inputs equals value of outputs.
/// `csprng` - Randomness.
fn sign_with_value_check<RNG: RngCore + CryptoRng>(
    prefix_hash: &[u8; 32],
    input_rows: &[Vec<(Address, Commitment)>],
    output_commitments_and_blindings: &[(Commitment, Blinding)],
    input_keys_and_blindings: &[(RistrettoPrivate, Blinding)],
    real_input_row: usize,
    check_value_is_preserved: bool,
    csprng: &mut RNG,
) -> Result<SignatureRctFull, Error> {
    let ring_size = input_rows.len(); // N rows, aka ring size.
    let num_inputs = input_rows[0].len(); // M columns, aka number of inputs.

    // Elements of `input_rows` must have the same length.
    for row in input_rows {
        if row.len() != num_inputs {
            return Err(Error::LengthMismatch(num_inputs, row.len()));
        }
    }

    // `input_keys_and_blindings` must contain an element for each input.
    if input_keys_and_blindings.len() != num_inputs {
        return Err(Error::LengthMismatch(
            num_inputs,
            input_keys_and_blindings.len(),
        ));
    }

    // `real_input_row` must be in [0,N-1].
    if real_input_row >= ring_size {
        return Err(Error::IndexOutOfBounds);
    }

    let G = GENERATORS.B;
    let H = GENERATORS.B_blinding;

    // Challenges generated from hashes of the L and R entries for each row.
    let mut c: Vec<Scalar> = vec![Scalar::zero(); ring_size];

    // Schnorr proof random blinding factor.
    let v: Vec<Scalar> = (0..=num_inputs).map(|_| Scalar::random(csprng)).collect();

    // Start at real_input_row (j), make all L(j,k), R(j,k), then L(j.M).
    let j = real_input_row;
    c[(j + 1) % ring_size] = {
        let real_inputs = &input_rows[j];

        // Start every hash with the prefix hash, so the signature signs the transaction.
        let mut row_hash = Blake2b::new();
        row_hash.input(prefix_hash);

        for (k, (y, _blinding)) in real_inputs.iter().enumerate() {
            // Standard linkable ring signature L/R terms for the owned inputs.
            let Hy = RistrettoPoint::hash_from_bytes::<Blake2b>(&y.to_bytes());
            let L_k = v[k] * G;
            let R_k = v[k] * Hy;
            row_hash.input(L_k.compress().as_bytes());
            row_hash.input(R_k.compress().as_bytes());
        }

        // Regular ring signature L term for balance proof.
        let L_M = v[num_inputs] * H;
        row_hash.input(L_M.compress().as_bytes());
        Scalar::from_hash::<Blake2b>(row_hash)
    };

    // Challenge responses. For the real input row it is the standard `r = v - cx`
    // for the mixin rows they are all random.
    //
    // r[j][k] = v[k] - c[j] * x
    let mut r: Vec<Vec<Scalar>> = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        r.push(Vec::with_capacity(num_inputs + 1));
        r[i].resize(num_inputs + 1, Scalar::zero());
    }

    // Sum of output commitments.
    let output_sum: RistrettoPoint = output_commitments_and_blindings
        .iter()
        .map(|(commitment, _blinding)| commitment.as_ref())
        .sum();

    let uncompressed_key_images: Vec<RistrettoPoint> = input_keys_and_blindings
        .iter()
        .map(|(onetime_private_key, _blinding)| compute_key_image_uncompressed(onetime_private_key))
        .collect();

    // Compute c[i] for i not equal to j.
    for n in 1..ring_size {
        let i = (j + n) % ring_size;
        let row: &Vec<(Address, Commitment)> = &input_rows[i];

        let mut row_hash = Blake2b::new();
        row_hash.input(prefix_hash);

        // Iterate over all the mixins in a row, appending their L/R to the hash buffer
        for (k, (y, _commitment)) in row.iter().enumerate() {
            // r is random for all mixins
            r[i][k] = Scalar::random(csprng);
            let Hy = RistrettoPoint::hash_from_bytes::<Blake2b>(&y.to_bytes());
            let L = r[i][k] * G + c[i] * y.as_ref();
            let R = r[i][k] * Hy + c[i] * uncompressed_key_images[k];

            row_hash.input(L.compress().as_bytes());
            row_hash.input(R.compress().as_bytes());
        }

        // The balance proof for this mixin row.
        {
            r[i][num_inputs] = Scalar::random(csprng);
            let row_commitment_sum: RistrettoPoint =
                row.iter().map(|(_, commitment)| commitment.0).sum();
            let y = output_sum - row_commitment_sum;
            let L = r[i][num_inputs] * H + c[i] * y;

            row_hash.input(L.compress().as_bytes());
        }

        c[(i + 1) % ring_size] = Scalar::from_hash::<Blake2b>(row_hash);
    }

    // The private key `z` for the "commitment to zero" `z*H`.
    // If the total value of outputs equals the total value of inputs, then the value components
    // of their commitments will cancel, leaving
    // sum_of_output_commitments - sum_of_input_commitments
    //  =  (sum_of_output_blindings - sum_of_input_blindings) * H
    //  =  z*H
    let z: Scalar = {
        let output_blinding_sum: Scalar = output_commitments_and_blindings
            .iter()
            .map(|(_, blinding)| blinding.0)
            .sum();

        let input_blinding_sum: Scalar = input_keys_and_blindings
            .iter()
            .map(|(_, blinding)| blinding.0)
            .sum();

        output_blinding_sum - input_blinding_sum
    };

    // Check that value is preserved.
    if check_value_is_preserved {
        let input_commitment_sum: RistrettoPoint = input_rows[real_input_row]
            .iter()
            .map(|(_address, commitment)| commitment.as_ref())
            .sum();

        let output_commitment_sum: RistrettoPoint = output_commitments_and_blindings
            .iter()
            .map(|(commitment, _)| commitment.as_ref())
            .sum();

        let difference: RistrettoPoint = output_commitment_sum - input_commitment_sum;
        if difference != (z * H) {
            return Err(Error::ValueNotConserved);
        }
    }

    // Create the real `r = v - cx` using the input address and balance proof secret keys.
    for k in 0..num_inputs {
        let x: Scalar = *input_keys_and_blindings[k].0.as_ref();
        r[j][k] = v[k] - c[j] * x;
    }

    r[j][num_inputs] = v[num_inputs] - c[j] * z;

    let challenge_responses: Vec<ChallengeResponse> = r
        .into_iter()
        .map(|row| {
            let curve_scalars: Vec<CurveScalar> = row.into_iter().map(CurveScalar::from).collect();
            ChallengeResponse::from(curve_scalars)
        })
        .collect();

    let key_images: Vec<KeyImage> = uncompressed_key_images
        .into_iter()
        .map(KeyImage::from)
        .collect();

    Ok(SignatureRctFull {
        key_images,
        challenge_responses,
        challenge: CurveScalar::from(c[0]),
    })
}

/// Verify a signature.
///
/// # Arguments

/// * `prefix_hash` - Hash of transaction prefix.
/// * `input_rows` - Input addresses and commitments.
/// * `output_commitments` - Output commitments.
/// * `signature` - Signature.
pub fn verify(
    prefix_hash: &[u8; 32],
    input_rows: &[Vec<(Address, Commitment)>],
    output_commitments: &[Commitment],
    signature: &SignatureRctFull,
) -> bool {
    let G = GENERATORS.B;
    let H = GENERATORS.B_blinding;
    let ring_size = input_rows.len(); // ring size = mixins_per_ring + 1.
    let num_inputs = input_rows[0].len();

    // Return false if the input_rows are of different lengths.
    for row in input_rows {
        if row.len() != num_inputs {
            return false;
        }
    }

    // challenge_responses should contain `ring_size = mixins_per_ring + 1` elements.
    if signature.challenge_responses.len() != ring_size {
        return false;
    }

    // Each ChallengeResponse should contain `num_inputs + 1` elements.
    for challenge_response in &signature.challenge_responses {
        if challenge_response.response.len() != num_inputs + 1 {
            return false;
        }
    }

    // The signature should contain one key image for each input.
    if signature.key_images.len() != num_inputs {
        return false;
    }

    // Sum the output commitments for the balance proofs.
    let output_commitment_sum: RistrettoPoint = output_commitments.iter().map(|c| c.as_ref()).sum();

    let maybe_I: Result<Vec<RistrettoPoint>, ()> = signature
        .key_images
        .iter()
        .map(|k| {
            <KeyImage as AsRef<CompressedRistretto>>::as_ref(k)
                .decompress()
                .ok_or(())
        })
        .collect();

    // Uncompressed key images.
    let I = match maybe_I {
        Ok(result) => result,
        Err(()) => {
            return false;
        }
    };

    // Protocol challenges, we will recreate them from the c[0] in the signature.
    let mut c: Vec<Scalar> = (0..ring_size).map(|_| Scalar::zero()).collect();

    // Iterate over the rows, constructing the next row's hash from the L/R terms.  wrap mod N.
    for i in 0..ring_size {
        let c_i = match i {
            0 => signature.challenge.into(),
            _ => c[i],
        };

        let mut row_hash = Blake2b::new();
        row_hash.input(prefix_hash);

        // Sum the input commitments for the balance proof.
        let input_commitment_sum: RistrettoPoint = input_rows[i]
            .iter()
            .map(|(_address, commitment)| commitment.as_ref())
            .sum();

        // Iterate over the inputs in the row, constructing the L/R terms for the hash.
        for k in 0..num_inputs {
            let (y, _commitment) = &input_rows[i][k];
            let Hy = RistrettoPoint::hash_from_bytes::<Blake2b>(&y.to_bytes());
            let r = signature.challenge_responses[i].response[k].as_ref();
            let L = r * G + c_i * y.as_ref();
            let R = r * Hy + c_i * I[k];
            row_hash.input(L.compress().as_bytes());
            row_hash.input(R.compress().as_bytes());
        }

        // Check the balance proof; subtract input commitments from outputs, use as key for Schnorr proof.
        {
            let y = output_commitment_sum - input_commitment_sum;
            let r = signature.challenge_responses[i].response[num_inputs].as_ref();
            let L = r * H + c_i * y;
            row_hash.input(L.compress().as_bytes());
        }

        // Assign the next c value in the ring.
        c[(i + 1) % ring_size] = Scalar::from_hash::<Blake2b>(row_hash);
    }

    // The signature is valid if c[0] was recomputed correctly.
    Into::<Scalar>::into(signature.challenge) == c[0]
}

#[cfg(test)]
mod test {
    use super::*;
    extern crate std;

    use crate::onetime_keys::compute_key_image;
    use keys::{FromRandom, RistrettoPrivate, RistrettoPublic};
    use mcrand::McRng;

    // Arguments for `sign`.
    struct SignatureParams {
        prefix_hash: [u8; 32],
        input_keys_and_blindings: Vec<(RistrettoPrivate, Blinding)>,
        input_rows: Vec<Vec<(Address, Commitment)>>,
        real_input_row: usize,
        output_commitments_and_blindings: Vec<(Commitment, Blinding)>,
    }

    impl SignatureParams {
        pub fn get_output_commitments(&self) -> Vec<Commitment> {
            self.output_commitments_and_blindings
                .iter()
                .map(|(commitment, _)| commitment.clone())
                .collect()
        }
    }

    // Returns valid parameters for creating a signature.
    fn get_signature_params<RNG: RngCore + CryptoRng>(
        num_inputs: usize,
        mixins_per_ring: usize,
        rng: &mut RNG,
    ) -> SignatureParams {
        let mut prefix_hash = [0u8; 32];
        rng.fill_bytes(&mut prefix_hash);

        // One-time private key for each spent input.
        let input_private_keys: Vec<RistrettoPrivate> = (0..num_inputs)
            .map(|_| RistrettoPrivate::from_random(rng))
            .collect();

        // Corresponding one-time public key for each spent input.
        let input_addresses: Vec<RistrettoPublic> = input_private_keys
            .iter()
            .map(RistrettoPublic::from)
            .collect();

        // Input Pedersen commitments. All inputs have random values.
        let input_values: Vec<Scalar> = (0..num_inputs)
            .map(|_| Scalar::from(rng.next_u64()))
            .collect();
        let input_blindings: Vec<Scalar> = (0..num_inputs).map(|_| Scalar::random(rng)).collect();
        let input_commitments: Vec<Commitment> = input_values
            .iter()
            .zip(input_blindings.iter())
            .map(|(value, blinding)| Commitment::from(GENERATORS.commit(*value, *blinding)))
            .collect();

        let input_keys_and_blindings: Vec<(RistrettoPrivate, Blinding)> = input_private_keys
            .iter()
            .cloned()
            .zip(input_blindings.iter().cloned().map(Blinding::from))
            .collect();

        // Output Pedersen commitments, one for each input.
        let output_values: Vec<Scalar> = input_values.clone();
        let output_blindings: Vec<Scalar> = (0..output_values.len())
            .map(|_| Scalar::random(rng))
            .collect();
        let output_commitments: Vec<Commitment> = output_values
            .iter()
            .zip(output_blindings.iter())
            .map(|(value, blinding)| Commitment::from(GENERATORS.commit(*value, *blinding)))
            .collect();

        let output_commitments_and_blindings: Vec<(Commitment, Blinding)> = output_commitments
            .iter()
            .cloned()
            .zip(output_blindings.iter().cloned().map(Blinding::from))
            .collect();

        let mut input_rows: Vec<Vec<(Address, Commitment)>> =
            Vec::with_capacity(mixins_per_ring + 1);

        let real_input_row = mixins_per_ring / 2;
        for i in 0..=mixins_per_ring {
            input_rows.push(Vec::with_capacity(num_inputs));
            if i == real_input_row {
                // The row of true inputs.
                for k in 0..num_inputs {
                    input_rows[i].push((input_addresses[k], input_commitments[k]));
                }
            } else {
                // A row of mixins.
                for _k in 0..num_inputs {
                    let address = RistrettoPublic::from_random(rng);
                    let commitment = {
                        let value = Scalar::random(rng);
                        let blinding = Scalar::random(rng);
                        Commitment::from(GENERATORS.commit(value, blinding))
                    };
                    input_rows[i].push((address, commitment));
                }
            }
        }

        SignatureParams {
            prefix_hash,
            input_keys_and_blindings,
            input_rows,
            real_input_row,
            output_commitments_and_blindings,
        }
    }

    #[test]
    // `verify` should accept valid signatures.
    fn test_verify_accepts_valid_signatures() {
        let mut rng = McRng::default();

        for num_inputs in &[1, 2, 4, 8] {
            for mixins_per_ring in &[1, 5, 10] {
                let signature_params =
                    get_signature_params(*num_inputs, *mixins_per_ring, &mut rng);

                // A valid signature.
                let signature = sign(
                    &signature_params.prefix_hash,
                    &signature_params.input_rows,
                    &signature_params.output_commitments_and_blindings,
                    &signature_params.input_keys_and_blindings,
                    signature_params.real_input_row,
                    &mut rng,
                )
                .unwrap();

                let output_commitments = signature_params.get_output_commitments();

                assert!(verify(
                    &signature_params.prefix_hash,
                    &signature_params.input_rows,
                    &output_commitments,
                    &signature
                ));
            }
        }
    }

    #[test]
    // The signature should contain the correct number of key images and challenge responses.
    fn test_sign_produces_signature_of_correct_size() {
        let mut rng = McRng::default();
        let num_inputs = 7;
        let mixins_per_ring = 16;

        let signature_params = get_signature_params(num_inputs, mixins_per_ring, &mut rng);

        let signature = sign(
            &signature_params.prefix_hash,
            &signature_params.input_rows,
            &signature_params.output_commitments_and_blindings,
            &signature_params.input_keys_and_blindings,
            signature_params.real_input_row,
            &mut rng,
        )
        .unwrap();

        // The signature should contain one key image for each input.
        assert_eq!(signature.key_images.len(), num_inputs);

        // challenge_responses should contain `ring_size = mixins_per_ring + 1` elements.
        assert_eq!(signature.challenge_responses.len(), (mixins_per_ring + 1));

        // Each ChallengeResponse should contain `num_inputs + 1` elements.
        for challenge_response in &signature.challenge_responses {
            assert_eq!(challenge_response.response.len(), num_inputs + 1);
        }
    }

    #[test]
    // Signing should fail if the sum of inputs does not equal the sum of outputs.
    fn test_sign_requires_value_to_be_preserved() {
        let mut rng = McRng::default();
        let num_inputs = 7;
        let mixins_per_ring = 16;

        let mut signature_params = get_signature_params(num_inputs, mixins_per_ring, &mut rng);

        // Remove one of the outputs.
        signature_params.output_commitments_and_blindings.pop();

        let result = sign(
            &signature_params.prefix_hash,
            &signature_params.input_rows,
            &signature_params.output_commitments_and_blindings,
            &signature_params.input_keys_and_blindings,
            signature_params.real_input_row,
            &mut rng,
        );

        match result {
            Err(Error::ValueNotConserved) => {} // expected
            _ => panic!(),
        }
    }

    #[test]
    // The signature should contain the correct key images for the spent inputs.
    fn test_signature_contains_correct_key_images() {
        let mut rng = McRng::default();
        let num_inputs = 7;
        let mixins_per_ring = 16;
        let signature_params = get_signature_params(num_inputs, mixins_per_ring, &mut rng);

        let signature = sign(
            &signature_params.prefix_hash,
            &signature_params.input_rows,
            &signature_params.output_commitments_and_blindings,
            &signature_params.input_keys_and_blindings,
            signature_params.real_input_row,
            &mut rng,
        )
        .unwrap();

        let expected_key_images: Vec<_> = signature_params
            .input_keys_and_blindings
            .iter()
            .map(|(key, _)| compute_key_image(key))
            .collect();

        assert_eq!(signature.key_images, expected_key_images);
    }

    #[test]
    // `sign` should return an error if input rows are of unequal sizes.
    fn test_sign_returns_error_mismatched_input_row_sizes() {
        let mut rng = McRng::default();
        let num_inputs = 7;
        let mixins_per_ring = 16;
        let mut signature_params = get_signature_params(num_inputs, mixins_per_ring, &mut rng);

        // Make one of the input_rows shorter than the others.
        signature_params.input_rows[0].pop();

        let result = sign(
            &signature_params.prefix_hash,
            &signature_params.input_rows,
            &signature_params.output_commitments_and_blindings,
            &signature_params.input_keys_and_blindings,
            signature_params.real_input_row,
            &mut rng,
        );

        match result {
            Err(Error::LengthMismatch(_, _)) => {} // expected
            _ => panic!(),
        }
    }

    #[test]
    // `sign` should return an error if `real_input_row` is out of bounds.
    fn test_sign_returns_error_real_input_row_out_of_bounds() {
        let mut rng = McRng::default();
        let num_inputs = 7;
        let mixins_per_ring = 16;
        let signature_params = get_signature_params(num_inputs, mixins_per_ring, &mut rng);

        // Out of bounds
        let wrong_input_row = 743;

        let result = sign(
            &signature_params.prefix_hash,
            &signature_params.input_rows,
            &signature_params.output_commitments_and_blindings,
            &signature_params.input_keys_and_blindings,
            wrong_input_row,
            &mut rng,
        );

        match result {
            Err(Error::IndexOutOfBounds) => {} // expected
            _ => panic!(),
        }
    }

    #[test]
    // `verify` should reject a signature that was signed with a wrong input private key.
    fn test_verify_rejects_signature_with_wrong_input_private_key() {
        let mut rng = McRng::default();
        let num_inputs = 7;
        let mixins_per_ring = 16;
        let mut signature_params = get_signature_params(num_inputs, mixins_per_ring, &mut rng);

        // Modify an input private key.
        signature_params.input_keys_and_blindings[3].0 = RistrettoPrivate::from_random(&mut rng);

        let signature = sign(
            &signature_params.prefix_hash,
            &signature_params.input_rows,
            &signature_params.output_commitments_and_blindings,
            &signature_params.input_keys_and_blindings,
            signature_params.real_input_row,
            &mut rng,
        )
        .unwrap();

        let output_commitments = signature_params.get_output_commitments();

        assert_eq!(
            false,
            verify(
                &signature_params.prefix_hash,
                &signature_params.input_rows,
                &output_commitments,
                &signature
            )
        );
    }

    #[test]
    // `verify` should reject a signature that was signed with a wrong input blinding.
    fn test_verify_rejects_signature_with_wrong_input_blinding() {
        let mut rng = McRng::default();
        let num_inputs = 7;
        let mixins_per_ring = 16;
        let mut signature_params = get_signature_params(num_inputs, mixins_per_ring, &mut rng);

        // Modify an input blinding.
        signature_params.input_keys_and_blindings[3].1 = Blinding::from_random(&mut rng);

        // Create an invalid signature (bypassing value preservation check).
        let invalid_signature = sign_with_value_check(
            &signature_params.prefix_hash,
            &signature_params.input_rows,
            &signature_params.output_commitments_and_blindings,
            &signature_params.input_keys_and_blindings,
            signature_params.real_input_row,
            false,
            &mut rng,
        )
        .unwrap();

        let output_commitments = signature_params.get_output_commitments();

        assert_eq!(
            false,
            verify(
                &signature_params.prefix_hash,
                &signature_params.input_rows,
                &output_commitments,
                &invalid_signature
            )
        );
    }

    #[test]
    // `verify` should return false if the number of key images and the number of challenge responses disagree.
    fn test_verify_rejects_signature_with_wrong_number_of_fields() {
        let mut rng = McRng::default();
        let num_inputs = 7;
        let mixins_per_ring = 16;
        let signature_params = get_signature_params(num_inputs, mixins_per_ring, &mut rng);

        let signature = sign(
            &signature_params.prefix_hash,
            &signature_params.input_rows,
            &signature_params.output_commitments_and_blindings,
            &signature_params.input_keys_and_blindings,
            signature_params.real_input_row,
            &mut rng,
        )
        .unwrap();

        // Remove a key image.
        {
            let mut signature = signature.clone();
            signature.key_images.pop();

            let output_commitments = signature_params.get_output_commitments();

            assert_eq!(
                false,
                verify(
                    &signature_params.prefix_hash,
                    &signature_params.input_rows,
                    &output_commitments,
                    &signature
                )
            );
        }

        // Add a key image.
        {
            let mut signature = signature.clone();
            signature
                .key_images
                .push(compute_key_image(&RistrettoPrivate::from_random(&mut rng)));

            let output_commitments = signature_params.get_output_commitments();

            assert_eq!(
                false,
                verify(
                    &signature_params.prefix_hash,
                    &signature_params.input_rows,
                    &output_commitments,
                    &signature
                )
            );
        }

        // Remove a challenge response.
        {
            let mut signature = signature.clone();
            signature.challenge_responses.pop();

            let output_commitments = signature_params.get_output_commitments();

            assert_eq!(
                false,
                verify(
                    &signature_params.prefix_hash,
                    &signature_params.input_rows,
                    &output_commitments,
                    &signature
                )
            );
        }

        // Add a challenge response.
        {
            let mut signature = signature.clone();
            let additional_challenge_response = signature.challenge_responses[0].clone();

            signature
                .challenge_responses
                .push(additional_challenge_response);

            let output_commitments = signature_params.get_output_commitments();

            assert_eq!(
                false,
                verify(
                    &signature_params.prefix_hash,
                    &signature_params.input_rows,
                    &output_commitments,
                    &signature
                )
            );
        }
    }

    #[test]
    // `verify` should fail if the signature is over the wrong message.
    fn test_verify_fails_for_wrong_message() {
        let mut rng = McRng::default();
        let num_inputs = 7;
        let mixins_per_ring = 16;

        let signature_params = get_signature_params(num_inputs, mixins_per_ring, &mut rng);

        let signature = sign(
            &signature_params.prefix_hash,
            &signature_params.input_rows,
            &signature_params.output_commitments_and_blindings,
            &signature_params.input_keys_and_blindings,
            signature_params.real_input_row,
            &mut rng,
        )
        .unwrap();

        let output_commitments = signature_params.get_output_commitments();

        let mut wrong_message = [0u8; 32];
        rng.fill_bytes(&mut wrong_message);

        assert_eq!(
            false,
            verify(
                &wrong_message,
                &signature_params.input_rows,
                &output_commitments,
                &signature
            )
        );
    }

    #[test]
    // `verify` should fail if the signature disagrees with an input Address.
    fn test_verify_fails_for_wrong_input_address() {
        let mut rng = McRng::default();
        let num_inputs = 7;
        let mixins_per_ring = 16;

        let mut signature_params = get_signature_params(num_inputs, mixins_per_ring, &mut rng);

        let signature = sign(
            &signature_params.prefix_hash,
            &signature_params.input_rows,
            &signature_params.output_commitments_and_blindings,
            &signature_params.input_keys_and_blindings,
            signature_params.real_input_row,
            &mut rng,
        )
        .unwrap();

        let output_commitments = signature_params.get_output_commitments();

        // Modify an Address in the first input_row.
        signature_params.input_rows[0][0].0 = Address::from_random(&mut rng);

        assert_eq!(
            false,
            verify(
                &signature_params.prefix_hash,
                &signature_params.input_rows,
                &output_commitments,
                &signature
            )
        );
    }

    #[test]
    // `verify` should fail if the signature disagrees with an input Commitment.
    fn test_verify_fails_for_wrong_input_commitment() {
        let mut rng = McRng::default();
        let num_inputs = 7;
        let mixins_per_ring = 16;

        let mut signature_params = get_signature_params(num_inputs, mixins_per_ring, &mut rng);

        let signature = sign(
            &signature_params.prefix_hash,
            &signature_params.input_rows,
            &signature_params.output_commitments_and_blindings,
            &signature_params.input_keys_and_blindings,
            signature_params.real_input_row,
            &mut rng,
        )
        .unwrap();

        let output_commitments = signature_params.get_output_commitments();

        // Modify a Commitment in the first input_row.
        signature_params.input_rows[0][0].1 = Commitment::from_random(&mut rng);

        assert_eq!(
            false,
            verify(
                &signature_params.prefix_hash,
                &signature_params.input_rows,
                &output_commitments,
                &signature
            )
        );
    }

    #[test]
    // `verify` should fail if the signature disagrees with an output Commitment.
    fn test_verify_fails_for_wrong_output_commitment() {
        let mut rng = McRng::default();
        let num_inputs = 7;
        let mixins_per_ring = 16;

        let signature_params = get_signature_params(num_inputs, mixins_per_ring, &mut rng);

        let signature = sign(
            &signature_params.prefix_hash,
            &signature_params.input_rows,
            &signature_params.output_commitments_and_blindings,
            &signature_params.input_keys_and_blindings,
            signature_params.real_input_row,
            &mut rng,
        )
        .unwrap();

        let mut output_commitments = signature_params.get_output_commitments();

        // Modify an output commitment.
        output_commitments[5] = Commitment::from_random(&mut rng);

        assert_eq!(
            false,
            verify(
                &signature_params.prefix_hash,
                &signature_params.input_rows,
                &output_commitments,
                &signature
            )
        );
    }

    #[test]
    // `verify` rejects a signature if the sum of inputs does not equal the sum of outputs.
    fn test_verify_requires_value_to_be_preserved() {
        let mut rng = McRng::default();
        let num_inputs = 7;
        let mixins_per_ring = 16;

        let mut signature_params = get_signature_params(num_inputs, mixins_per_ring, &mut rng);

        // Modify an output commitment.
        let new_blinding = Scalar::random(&mut rng);
        let new_value = Scalar::from(1_000_000u64);
        let new_commitment = Commitment::from(GENERATORS.commit(new_value, new_blinding));

        signature_params.output_commitments_and_blindings[3] =
            (new_commitment, CurveScalar::from(new_blinding));

        // Create an invalid signature (bypassing the value preservation check).
        let invalid_signature = sign_with_value_check(
            &signature_params.prefix_hash,
            &signature_params.input_rows,
            &signature_params.output_commitments_and_blindings,
            &signature_params.input_keys_and_blindings,
            signature_params.real_input_row,
            false,
            &mut rng,
        )
        .unwrap();

        let output_commitments = signature_params.get_output_commitments();

        assert_eq!(
            false,
            verify(
                &signature_params.prefix_hash,
                &signature_params.input_rows,
                &output_commitments,
                &invalid_signature
            )
        );
    }
}
