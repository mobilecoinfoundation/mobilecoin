// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A commitment to an output's amount, denominated in picoMOB.
//!
//! Amounts are implemented as Pedersen commitments. The associated private keys
//! are "masked" using a shared secret.

#![cfg_attr(test, allow(clippy::unnecessary_operation))]

use crate::{
    domain_separators::{
        AMOUNT_BLINDING_DOMAIN_TAG, AMOUNT_TOKEN_ID_DOMAIN_TAG, AMOUNT_VALUE_DOMAIN_TAG,
    },
    ring_signature::generators,
    token::TokenId,
};
use alloc::vec::Vec;
use core::convert::TryInto;
use crc::Crc;
use curve25519_dalek::scalar::Scalar;
use mc_crypto_digestible::Digestible;
use mc_crypto_hashes::{Blake2b512, Digest};
use mc_crypto_keys::RistrettoPublic;
use prost::Message;
use serde::{Deserialize, Serialize};

mod commitment;
mod compressed_commitment;
mod error;

pub use commitment::Commitment;
pub use compressed_commitment::CompressedCommitment;
pub use error::AmountError;

/// The data blinded by a MobileCoin amount commitment
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AmountData {
    /// The "raw" value of this amount as a u64
    pub value: u64,
    /// The token-id which is the denomination of this amount
    pub token_id: TokenId,
}

/// A commitment to an amount of MobileCoin, denominated in picoMOB.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Message, Digestible)]
pub struct Amount {
    /// A Pedersen commitment `v*H + b*G` to a quantity `v` of MobileCoin, with
    /// blinding `b`,
    #[prost(message, required, tag = "1")]
    pub commitment: CompressedCommitment,

    /// `masked_value = value XOR_8 Blake2B(value_mask | shared_secret)`
    #[prost(fixed64, required, tag = "2")]
    pub masked_value: u64,

    /// `masked_token_id = token_id XOR_8 Blake2B(token_id_mask |
    /// shared_secret)` 4 bytes long when used, 0 bytes for older amounts
    /// that don't have this.
    #[prost(bytes, tag = "3")]
    pub masked_token_id: Vec<u8>,
}

impl Amount {
    /// Creates a commitment `value*H + blinding*G`, and "masks" the commitment
    /// secrets so that they can be recovered by the recipient.
    ///
    /// # Arguments
    /// * `data` - The committed value `v` and token id `i`, in picoMOB.
    /// * `shared_secret` - The shared secret, e.g. `rB` for transaction private
    ///   key `r` and recipient public key `B`.
    #[inline]
    pub fn new(data: AmountData, shared_secret: &RistrettoPublic) -> Result<Amount, AmountError> {
        // The blinding is `Blake2B("blinding" | shared_secret)`
        let blinding: Scalar = get_blinding(shared_secret);

        // Pedersen generators
        let generator = generators(*data.token_id);

        // Pedersen commitment `v*H_i + b*G`.
        let commitment = CompressedCommitment::new(data.value, blinding, &generator);

        // The value is XORed with the first 8 bytes of the mask.
        // `v XOR_8 Scalar::from_hash(Blake2B(value_mask | shared_secret))`
        let masked_value: u64 = data.value ^ get_value_mask(shared_secret);

        // The token_id is XORed with the first 4 bytes of the mask.
        // `v XOR_4 Blake2B(token_id_mask | shared_secret)`
        let masked_token_id_val: u32 = *data.token_id ^ get_token_id_mask(shared_secret);
        let masked_token_id = masked_token_id_val.to_le_bytes().to_vec();

        Ok(Amount {
            commitment,
            masked_value,
            masked_token_id,
        })
    }

    /// Returns the value `v` and blinding `b` in the commitment `v*H + b*G`.
    ///
    /// Value is denominated in picoMOB.
    ///
    /// # Arguments
    /// * `shared_secret` - The shared secret, e.g. `rB`.
    pub fn get_value(
        &self,
        shared_secret: &RistrettoPublic,
    ) -> Result<(AmountData, Scalar), AmountError> {
        let (expected_commitment, amount_data, blinding) =
            Self::compute_commitment(self.masked_value, &self.masked_token_id, shared_secret)?;
        if self.commitment != expected_commitment {
            // The commitment does not agree with the provided value and blinding.
            // This either means that the commitment does not correspond to the shared
            // secret, or that the amount is malformed (and is probably not
            // spendable).
            return Err(AmountError::InconsistentCommitment);
        }

        Ok((amount_data, blinding))
    }

    /// Compute the crc32 of the compressed commitment
    pub fn commitment_crc32(&self) -> u32 {
        Self::compute_commitment_crc32(&self.commitment)
    }

    /// Recovers an Amount from only the masked value and masked_token_id, and
    /// shared secret.
    ///
    /// Note: This fails and produces gibberish if the shared secret is wrong.
    ///
    /// * You should confirm by checking against the real commitment, or the the
    ///   crc32 of commitment.
    ///
    /// Arguments:
    /// * masked_value: u64
    /// * masked_token_id: &[u8], either 0 or 4 bytes
    /// * shared_secret: The shared secret curve point
    ///
    /// Returns:
    /// * Amount
    /// * AmountData (token id and value)
    /// or
    /// * An amount error
    pub fn reconstruct(
        masked_value: u64,
        masked_token_id: &[u8],
        shared_secret: &RistrettoPublic,
    ) -> Result<(Self, AmountData), AmountError> {
        let (expected_commitment, amount_data, _) =
            Self::compute_commitment(masked_value, masked_token_id, shared_secret)?;

        let result = Self {
            commitment: expected_commitment,
            masked_value,
            masked_token_id: masked_token_id.to_vec(),
        };

        Ok((result, amount_data))
    }

    fn compute_commitment(
        masked_value: u64,
        masked_token_id: &[u8],
        shared_secret: &RistrettoPublic,
    ) -> Result<(CompressedCommitment, AmountData, Scalar), AmountError> {
        let token_id = TokenId::from(Self::unmask_token_id(masked_token_id, shared_secret)?);
        let value: u64 = Self::unmask_value(masked_value, shared_secret);
        let blinding = get_blinding(shared_secret);

        // Pedersen generators
        let generator = generators(*token_id);

        let expected_commitment = CompressedCommitment::new(value, blinding, &generator);

        Ok((
            expected_commitment,
            AmountData { value, token_id },
            blinding,
        ))
    }

    fn compute_commitment_crc32(commitment: &CompressedCommitment) -> u32 {
        Crc::<u32>::new(&crc::CRC_32_ISO_HDLC).checksum(commitment.point.as_bytes())
    }

    /// Reveals `masked_value`.
    fn unmask_value(masked_value: u64, shared_secret: &RistrettoPublic) -> u64 {
        masked_value ^ get_value_mask(shared_secret)
    }

    /// Reveals `masked_token_id`, with backwards compat
    fn unmask_token_id(
        masked_token_id: &[u8],
        shared_secret: &RistrettoPublic,
    ) -> Result<u32, AmountError> {
        match masked_token_id.len() {
            0 => Ok(0),
            4 => {
                let masked_token_id_val = u32::from_le_bytes(masked_token_id.try_into().unwrap());
                Ok(masked_token_id_val ^ get_token_id_mask(shared_secret))
            }
            _ => Err(AmountError::InvalidMaskedTokenId),
        }
    }
}

/// Computes `Blake2B(value_mask | shared_secret)`, hashed to a Ristretto
/// scalar, then interprets the first 8 canonical bytes as a u64 number in
/// little-endian representation.
///
/// # Arguments
/// * `shared_secret` - The shared secret, e.g. `rB`.
fn get_value_mask(shared_secret: &RistrettoPublic) -> u64 {
    let mut hasher = Blake2b512::new();
    hasher.update(&AMOUNT_VALUE_DOMAIN_TAG);
    hasher.update(&shared_secret.to_bytes());
    let scalar = Scalar::from_hash(hasher);
    let mut temp = [0u8; 8];
    temp.copy_from_slice(&scalar.as_bytes()[0..8]);
    u64::from_le_bytes(temp)
}

/// Computes `Blake2B(token_id_mask | shared_secret)`,
/// then interprets the first 4 canonical bytes as a u32 number in
/// little-endian representation.
///
/// # Arguments
/// * `shared_secret` - The shared secret, e.g. `rB`.
fn get_token_id_mask(shared_secret: &RistrettoPublic) -> u32 {
    let mut hasher = Blake2b512::new();
    hasher.update(&AMOUNT_TOKEN_ID_DOMAIN_TAG);
    hasher.update(&shared_secret.to_bytes());
    u32::from_le_bytes(hasher.finalize()[0..4].try_into().unwrap())
}

/// Computes `Blake2B("blinding" | shared_secret)`.
///
/// # Arguments
/// * `shared_secret` - The shared secret, e.g. `rB`.
fn get_blinding(shared_secret: &RistrettoPublic) -> Scalar {
    let mut hasher = Blake2b512::new();
    hasher.update(&AMOUNT_BLINDING_DOMAIN_TAG);
    hasher.update(&shared_secret.to_bytes());
    Scalar::from_hash(hasher)
}

#[cfg(test)]
mod amount_tests {
    use crate::{
        amount::{get_blinding, Amount, AmountData, AmountError},
        proptest_fixtures::*,
        ring_signature::generators,
        CompressedCommitment,
    };
    use proptest::prelude::*;

    proptest! {

            #[test]
            /// Amount::new() should return Ok for valid values and blindings.
            fn test_new_ok(
                value in any::<u64>(),
                token_id in any::<u32>(),
                shared_secret in arbitrary_ristretto_public()) {
                    let amount_data = AmountData { value, token_id: token_id.into() };
                assert!(Amount::new(amount_data, &shared_secret).is_ok());
            }

            #[test]
            #[allow(non_snake_case)]
            /// amount.commitment should agree with the value and blinding.
            fn test_commitment(
                value in any::<u64>(),
                token_id in any::<u32>(),
                shared_secret in arbitrary_ristretto_public()) {
                    let amount_data = AmountData { value, token_id: token_id.into() };
                    let amount = Amount::new(amount_data, &shared_secret).unwrap();
                    let blinding = get_blinding(&shared_secret);
                    let expected_commitment = CompressedCommitment::new(value, blinding.into(), &generators(token_id));
                    assert_eq!(amount.commitment, expected_commitment);
            }

            #[test]
            /// amount.unmask_value should return the value used to construct the amount.
            fn test_unmask_value(
                value in any::<u64>(),
                token_id in any::<u32>(),
                shared_secret in arbitrary_ristretto_public())
            {
                let amount_data = AmountData { value, token_id: token_id.into() };
                let amount = Amount::new(amount_data, &shared_secret).unwrap();
                assert_eq!(
                    value,
                    Amount::unmask_value(amount.masked_value, &shared_secret)
                );
            }

            #[test]
            /// get_value should return the correct value and blinding.
            fn test_get_value_ok(
                value in any::<u64>(),
                token_id in any::<u32>(),
                shared_secret in arbitrary_ristretto_public()) {
                let amount_data = AmountData { value, token_id: token_id.into() };
                let amount = Amount::new(amount_data.clone(), &shared_secret).unwrap();
                let result = amount.get_value(&shared_secret);
                let blinding = get_blinding(&shared_secret);
                let expected = Ok((amount_data, blinding));
                assert_eq!(result, expected);
            }


            #[test]
            /// get_value should return InconsistentCommitment if the masked value is incorrect.
            fn test_get_value_incorrect_masked_value(
                value in any::<u64>(),
                token_id in any::<u32>(),
                other_masked_value in any::<u64>(),
                shared_secret in arbitrary_ristretto_public())
            {
                // Mutate amount to use a different masked value.
                // With high probability, amount.masked_value won't equal other_masked_value.
                let amount_data = AmountData { value, token_id: token_id.into() };
                let mut amount = Amount::new(amount_data, &shared_secret).unwrap();
                amount.masked_value = other_masked_value;
                let result = amount.get_value(&shared_secret);
                let expected = Err(AmountError::InconsistentCommitment);
                assert_eq!(result, expected);
            }

            #[test]
            /// get_value should return an Error if shared_secret is incorrect.
            fn test_get_value_invalid_shared_secret(
                value in any::<u64>(),
                token_id in any::<u32>(),
                shared_secret in arbitrary_ristretto_public(),
                other_shared_secret in arbitrary_ristretto_public(),
            ) {
                let amount_data = AmountData { value, token_id: token_id.into() };
                let amount = Amount::new(amount_data,  &shared_secret).unwrap();
                let result = amount.get_value(&other_shared_secret);
                let expected = Err(AmountError::InconsistentCommitment);
                assert_eq!(result, expected);
            }
    }
}
