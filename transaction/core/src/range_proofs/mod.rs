// Copyright (c) 2018-2021 The MobileCoin Foundation

extern crate alloc;
use alloc::vec::Vec;
use bulletproofs::RangeProof;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

pub mod error;
use crate::{
    domain_separators::BULLETPROOF_DOMAIN_TAG,
    ring_signature::{BP_GENERATORS, GENERATORS},
};
use error::Error;

/// Create an aggregated 64-bit rangeproof for a set of values.
///
/// Creates a proof that each secret value is in the range [0,2^64).
///
/// # Arguments
/// `values` - Secret values that we want to prove are in [0,2^64).
/// `blindings` - Pedersen commitment blinding for each value.
///
/// # Returns
/// The proof and the Pedersen commitments from `values` and `blindings` (padded
/// to a power of 2).
pub fn generate_range_proofs<T: RngCore + CryptoRng>(
    values: &[u64],
    blindings: &[Scalar],
    rng: &mut T,
) -> Result<(RangeProof, Vec<CompressedRistretto>), Error> {
    // Most of this comes directly from the example at
    // https://doc-internal.dalek.rs/bulletproofs/struct.RangeProof.html#example-1

    // Aggregated rangeproofs operate on sets of `m` values, where `m` must be a
    // power of 2. If the number of inputs is not a power of 2, pad them.
    let values_padded: Vec<u64> = resize_slice_to_pow2::<u64>(values)?;
    let blindings_padded: Vec<Scalar> = resize_slice_to_pow2::<Scalar>(blindings)?;

    // Create a 64-bit RangeProof and corresponding commitments.
    RangeProof::prove_multiple_with_rng(
        &BP_GENERATORS,
        &GENERATORS,
        &mut Transcript::new(BULLETPROOF_DOMAIN_TAG.as_ref()),
        &values_padded,
        &blindings_padded,
        64,
        rng,
    )
    .map_err(Error::from)
}

/// Verifies an aggregated 64-bit RangeProof for the given value commitments.
///
/// Proves that the corresponding values lie in the range [0,2^64).
///
/// # Arguments
/// `range_proof` - A RangeProof.
/// `commitments` - Commitments to secret values that lie in the range [0,2^64).
/// `rng` - Randomness.
pub fn check_range_proofs<T: RngCore + CryptoRng>(
    range_proof: &RangeProof,
    commitments: &[CompressedRistretto],
    rng: &mut T,
) -> Result<(), Error> {
    // The length of `commitments` must be a power of 2. If not, resize it.
    let resized_commitments = resize_slice_to_pow2::<CompressedRistretto>(commitments)?;
    range_proof
        .verify_multiple_with_rng(
            &BP_GENERATORS,
            &GENERATORS,
            &mut Transcript::new(BULLETPROOF_DOMAIN_TAG.as_ref()),
            &resized_commitments,
            64,
            rng,
        )
        .map_err(Error::from)
}

/// Return a vector which is the slice plus enough of the final element such
/// that the length of the vector is a power of two.
///
/// If the next power of two is greater than the type's maximum value, an Error
/// is returned.
///
/// # Arguments
/// `slice` - (in) the slice with the data to use
fn resize_slice_to_pow2<T: Clone>(slice: &[T]) -> Result<Vec<T>, Error> {
    let len: usize = slice.len();
    if let Some(next_power_of_two) = len.checked_next_power_of_two() {
        let diff = next_power_of_two - len;
        let mut pow2_slice: Vec<T> = Vec::with_capacity(next_power_of_two);
        pow2_slice.extend_from_slice(slice);
        pow2_slice.resize(slice.len() + diff, slice[slice.len() - 1].clone());
        Ok(pow2_slice)
    } else {
        // The next power of two would exceed the maximum value of usize.
        Err(Error::ResizeError)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::RngCore;

    fn generate_and_check(values: Vec<u64>, blindings: Vec<Scalar>) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let (proof, commitments) = generate_range_proofs(&values, &blindings, &mut rng).unwrap();

        match check_range_proofs(&proof, &commitments, &mut rng) {
            Ok(_) => {} // This is expected.
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn test_pow2_number_of_inputs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let vals: Vec<u64> = (0..2).map(|_| rng.next_u64()).collect();
        let blindings: Vec<Scalar> = vals.iter().map(|_| Scalar::random(&mut rng)).collect();
        generate_and_check(vals, blindings);
    }

    #[test]
    fn test_not_pow2_number_of_inputs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let vals: Vec<u64> = (0..9).map(|_| rng.next_u64()).collect();
        let blindings: Vec<Scalar> = vals.iter().map(|_| Scalar::random(&mut rng)).collect();
        generate_and_check(vals, blindings);
    }

    #[test]
    // `check_range_proofs` should return an error if the commitments do not agree
    // with the proof.
    fn test_check_range_proofs_rejects_wrong_commitments() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let num_values: usize = 4;
        let values: Vec<u64> = (0..num_values).map(|_| rng.next_u64()).collect();
        let blindings: Vec<Scalar> = (0..num_values).map(|_| Scalar::random(&mut rng)).collect();
        let (proof, commitments) = generate_range_proofs(&values, &blindings, &mut rng).unwrap();

        // Modify a commitment.
        let mut wrong_commitments = commitments.clone();
        wrong_commitments[0] = RistrettoPoint::random(&mut rng).compress();

        match check_range_proofs(&proof, &wrong_commitments, &mut rng) {
            Ok(_) => panic!(),
            Err(_e) => {} // This is expected.
        }
    }
}
