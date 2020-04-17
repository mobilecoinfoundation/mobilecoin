// Copyright (c) 2018-2020 MobileCoin Inc.

//! A commitment to an output's amount, denominated in picoMOB.
//!
//! Amounts are implemented as Pedersen commitments. The associated private keys are "masked" using
//! a shared secret.

#![cfg_attr(test, allow(clippy::unnecessary_operation))]

use crate::{
    ring_signature::{CurveScalar, GENERATORS},
    CompressedCommitment,
};
use blake2::{Blake2b, Digest};
use curve25519_dalek::scalar::Scalar;
use digestible::Digestible;
use failure::Fail;
use keys::RistrettoPublic;
use mcserial::ReprBytes32;
use prost::Message;
use serde::{Deserialize, Serialize};

/// Errors that can occur when constructing an amount.
#[derive(Debug, Fail, Eq, PartialEq)]
pub enum AmountError {
    /// The masked value, masked blinding, or shared secret are not consistent with the commitment.
    #[fail(display = "Inconsistent Commitment")]
    InconsistentCommitment,
}

/// Value mask hash function domain separator.
const VALUE_MASK: &str = "amount_value_mask";

/// Blinding mask hash function domain separator.
const BLINDING_MASK: &str = "amount_blinding_mask";

// The "blinding factor" in a Pedersen commitment.
pub type Blinding = CurveScalar;

/// A commitment to an amount of MobileCoin, denominated in picoMOB.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Message, Digestible)]
pub struct Amount {
    /// A Pedersen commitment `v*G + b*H` to a quantity `v` of MobileCoin, with blinding `b`,
    #[prost(message, required, tag = "1")]
    pub commitment: CompressedCommitment,

    /// `masked_value = value XOR_8 Blake2B(value_mask | shared_secret)`
    #[prost(uint64, required, tag = "2")]
    pub masked_value: u64,

    /// `masked_blinding = blinding + Blake2B(blinding_mask | shared_secret))
    #[prost(message, required, tag = "3")]
    pub masked_blinding: Blinding,
}

impl Amount {
    /// Creates a commitment `value*G + blinding*H`, and "masks" the commitment secrets
    /// so that they can be recovered by the recipient.
    ///
    /// # Arguments
    /// * `value` - The committed value `v`, in picoMOB.
    /// * `blinding` - The blinding `b`.
    /// * `shared_secret` - The shared secret, e.g. `rB` for transaction private key `r` and recipient public key `B`.
    #[inline]
    pub fn new(
        value: u64,
        blinding: Blinding,
        shared_secret: &RistrettoPublic,
    ) -> Result<Amount, AmountError> {
        // Pedersen commitment `v*G + b*H`.
        let commitment = CompressedCommitment::new(value, blinding.into());

        // The value is XORed with the first 8 bytes of the mask.
        // `v XOR_8 Blake2B(value_mask | shared_secret)`
        let masked_value: u64 = {
            let mask: u64 = {
                let mut temp = [0u8; 8];
                temp.copy_from_slice(&get_value_mask(&shared_secret).as_bytes()[0..8]);
                u64::from_le_bytes(temp)
            };
            value ^ mask
        };

        // `b + Blake2B("blinding_mask" | shared_secret)`
        let masked_blinding: Scalar = {
            let mask = get_blinding_mask(&shared_secret);
            blinding.as_ref() + mask
        };

        Ok(Amount {
            commitment,
            masked_value,
            masked_blinding: Blinding::from(masked_blinding),
        })
    }

    /// Returns the value `v` and blinding `b` in the commitment `v*G + b*H`.
    ///
    /// Value is denominated in picoMOB.
    ///
    /// # Arguments
    /// * `shared_secret` - The shared secret, e.g. `rB`.
    pub fn get_value(
        &self,
        shared_secret: &RistrettoPublic,
    ) -> Result<(u64, Blinding), AmountError> {
        let value: u64 = self.unmask_value(shared_secret);
        let blinding = self.unmask_blinding(shared_secret);

        let expected_commitment = CompressedCommitment::new(value, blinding.into());
        if self.commitment != expected_commitment {
            // The commitment does not agree with the provided value and blinding.
            // This either means that the commitment does not correspond to the shared secret, or
            // that the amount is malformed (and is probably not spendable).
            return Err(AmountError::InconsistentCommitment);
        }

        Ok((value, blinding))
    }

    /// Reveals `masked_value`.
    fn unmask_value(&self, shared_secret: &RistrettoPublic) -> u64 {
        let mask: u64 = {
            let mut temp = [0u8; 8];
            temp.copy_from_slice(&get_value_mask(&shared_secret).as_bytes()[0..8]);
            u64::from_le_bytes(temp)
        };
        self.masked_value ^ mask
    }

    /// Reveals `masked_blinding`.
    fn unmask_blinding(&self, shared_secret: &RistrettoPublic) -> Blinding {
        let mask = get_blinding_mask(shared_secret);
        let masked_blinding: Scalar = self.masked_blinding.into();
        Blinding::from(masked_blinding - mask)
    }
}

/// Computes `Blake2B(value_mask | shared_secret)`.
///
/// # Arguments
/// * `shared_secret` - The shared secret, e.g. `rB`.
fn get_value_mask(shared_secret: &RistrettoPublic) -> Scalar {
    let mut hasher = Blake2b::new();
    hasher.input(&VALUE_MASK);
    hasher.input(&shared_secret.to_bytes());
    Scalar::from_hash(hasher)
}

/// Computes `Blake2B(blinding_mask | shared_secret)`.
///
/// # Arguments
/// * `shared_secret` - The shared secret, e.g. `rB`.
fn get_blinding_mask(shared_secret: &RistrettoPublic) -> Scalar {
    let mut hasher = Blake2b::new();
    hasher.input(&BLINDING_MASK);
    hasher.input(&shared_secret.to_bytes());
    Scalar::from_hash(hasher)
}

#[cfg(test)]
mod amount_tests {
    use crate::{
        amount::{Amount, AmountError},
        proptest_fixtures::*,
        ring_signature::{Scalar, GENERATORS},
        CompressedCommitment,
    };
    use proptest::prelude::*;

    proptest! {

            #[test]
            /// Amount::new() should return Ok for valid values and blindings.
            fn test_new_ok(
                value in any::<u64>(),
                blinding in arbitrary_blinding(),
                shared_secret in arbitrary_ristretto_public()) {
                assert!(Amount::new(value, blinding, &shared_secret).is_ok());
            }

            #[test]
            #[allow(non_snake_case)]
            /// amount.commitment should agree with the value and blinding.
            fn test_commitment(
                value in any::<u64>(),
                blinding in arbitrary_blinding(),
                shared_secret in arbitrary_ristretto_public()) {
                    let amount = Amount::new(value, blinding,  &shared_secret).unwrap();
                    let expected_commitment = CompressedCommitment::new(value, blinding.into());
                    assert_eq!(amount.commitment, expected_commitment);
            }

            #[test]
            /// amount.unmask_value should return the value used to construct the amount.
            fn test_unmask_value(
                value in any::<u64>(),
                blinding in arbitrary_blinding(),
                shared_secret in arbitrary_ristretto_public())
            {

                let amount = Amount::new(value, blinding,  &shared_secret).unwrap();
                assert_eq!(
                    value,
                    amount.unmask_value(&shared_secret)
                );
            }

            #[test]
            /// amount.unmask_blinding should return the blinding used to construct the amount.
            fn test_unmask_blinding(
                value in any::<u64>(),
                blinding in arbitrary_blinding(),
                shared_secret in arbitrary_ristretto_public())
            {
                let amount = Amount::new(value, blinding,  &shared_secret).unwrap();
                assert_eq!(
                    amount.unmask_blinding(&shared_secret),
                    blinding
                );
            }

            #[test]
            /// get_value should return the correct value and blinding.
            fn test_get_value_ok(
                value in any::<u64>(),
                blinding in arbitrary_blinding(),
                shared_secret in arbitrary_ristretto_public()) {

                let amount = Amount::new(value, blinding,  &shared_secret).unwrap();
                let result = amount.get_value(&shared_secret);
                let expected = Ok((value, blinding));
                assert_eq!(result, expected);
            }


            #[test]
            /// get_value should return InconsistentCommitment if the masked value is incorrect.
            fn test_get_value_incorrect_masked_value(
                value in any::<u64>(),
                other_masked_value in any::<u64>(),
                blinding in arbitrary_blinding(),
                shared_secret in arbitrary_ristretto_public())
            {
                // Mutate amount to use a different masked value.
                // With overwhelming probability, amount.masked_value won't equal other_masked_value.
                let mut amount = Amount::new(value, blinding, &shared_secret).unwrap();
                amount.masked_value = other_masked_value;
                let result = amount.get_value(&shared_secret);
                let expected = Err(AmountError::InconsistentCommitment);
                assert_eq!(result, expected);
            }

            #[test]
            /// get_value should return InconsistentCommitment if the masked blinding is incorrect.
            fn test_get_value_incorrect_blinding(
                value in any::<u64>(),
                blinding in arbitrary_blinding(),
                other_masked_blinding in arbitrary_curve_scalar(),
                shared_secret in arbitrary_ristretto_public())
            {
                // Mutate amount to use a other_masked_blinding.
                let mut amount = Amount::new(value, blinding, &shared_secret).unwrap();
                amount.masked_blinding = other_masked_blinding;
                let result = amount.get_value(&shared_secret);
                let expected = Err(AmountError::InconsistentCommitment);
                assert_eq!(result, expected);
            }

            #[test]
            /// get_value should return an Error if shared_secret is incorrect.
            fn test_get_value_invalid_shared_secret(
                value in any::<u64>(),
                blinding in arbitrary_blinding(),
                shared_secret in arbitrary_ristretto_public(),
                other_shared_secret in arbitrary_ristretto_public(),
            ) {
                let amount = Amount::new(value, blinding,  &shared_secret).unwrap();
                let result = amount.get_value(&other_shared_secret);
                let expected = Err(AmountError::InconsistentCommitment);
                assert_eq!(result, expected);
            }
    }
}
