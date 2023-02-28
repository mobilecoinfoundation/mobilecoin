// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A commitment to an output's amount, denominated in picoMOB.
//!
//! Amounts are implemented as Pedersen commitments. The associated private keys
//! are "masked" using a shared secret.

use alloc::vec::Vec;
use core::convert::TryInto;

use crate::{
    amount::{Amount, AmountError},
    domain_separators::{
        AMOUNT_BLINDING_DOMAIN_TAG, AMOUNT_TOKEN_ID_DOMAIN_TAG, AMOUNT_VALUE_DOMAIN_TAG,
    },
    TokenId,
};

use mc_crypto_digestible::Digestible;
use mc_crypto_hashes::{Blake2b512, Digest};
use mc_crypto_keys::RistrettoPublic;
use mc_crypto_ring_signature::{generators, CompressedCommitment, Scalar};

use crc::Crc;
#[cfg(feature = "prost")]
use prost::Message;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A commitment to an amount of MobileCoin or a related token, as it appears on
/// the blockchain. This is a "blinded" commitment, and only the sender and
/// receiver know the value and token id.
#[derive(Clone, Digestible, Eq, Hash, PartialEq, Zeroize)]
#[digestible(name = "Amount")]
#[cfg_attr(feature = "prost", derive(Message))]
#[cfg_attr(not(feature = "prost"), derive(Debug))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct MaskedAmountV1 {
    /// A Pedersen commitment `v*H + b*G` to a quantity `v` of MobileCoin or a
    /// related token, with blinding `b`,
    #[cfg_attr(feature = "prost", prost(message, required, tag = "1"))]
    pub commitment: CompressedCommitment,

    /// `masked_value = value XOR_8 Blake2B(value_mask | shared_secret)`
    #[cfg_attr(feature = "prost", prost(fixed64, required, tag = "2"))]
    pub masked_value: u64,

    /// `masked_token_id = token_id XOR_8 Blake2B(token_id_mask |
    /// shared_secret)` 8 bytes long when used, 0 bytes for older amounts
    /// that don't have this.
    #[cfg_attr(feature = "prost", prost(bytes, tag = "3"))]
    pub masked_token_id: Vec<u8>,
}

impl MaskedAmountV1 {
    /// Creates a commitment `value*H + blinding*G`, and "masks" the commitment
    /// secrets so that they can be recovered by the recipient.
    ///
    /// # Arguments
    /// * `amount` - The amount information to be masked
    /// * `tx_out_shared_secret` - The shared secret, e.g. `rB` for transaction
    ///   private key `r` and recipient public key `B`.
    #[inline]
    pub fn new(
        amount: Amount,
        tx_out_shared_secret: &RistrettoPublic,
    ) -> Result<Self, AmountError> {
        // The blinding is `Blake2B("blinding" | shared_secret)`
        let blinding: Scalar = get_blinding(tx_out_shared_secret);

        // Pedersen generators
        let generator = generators(*amount.token_id);

        // Pedersen commitment `v*H_i + b*G`.
        let commitment = CompressedCommitment::new(amount.value, blinding, &generator);

        // The value is XORed with the first 8 bytes of the mask.
        // `v XOR_8 Scalar::from_hash(Blake2B(value_mask | shared_secret))`
        let masked_value: u64 = amount.value ^ get_value_mask(tx_out_shared_secret);

        // The token_id is XORed with the first 8 bytes of the mask.
        // `v XOR_4 Blake2B(token_id_mask | shared_secret)`
        let masked_token_id_val: u64 = *amount.token_id ^ get_token_id_mask(tx_out_shared_secret);
        let masked_token_id = masked_token_id_val.to_le_bytes().to_vec();

        Ok(MaskedAmountV1 {
            commitment,
            masked_value,
            masked_token_id,
        })
    }

    /// Returns the amount underlying the masked amount, given the TxOut shared
    /// secret.
    ///
    /// Value is denominated in picoMOB.
    ///
    /// # Arguments
    /// * `tx_out_shared_secret` - The shared secret, e.g. `rB`.
    pub fn get_value(
        &self,
        tx_out_shared_secret: &RistrettoPublic,
    ) -> Result<(Amount, Scalar), AmountError> {
        let (expected_commitment, amount, blinding) = Self::compute_commitment(
            self.masked_value,
            &self.masked_token_id,
            tx_out_shared_secret,
        )?;
        if self.commitment != expected_commitment {
            // The commitment does not agree with the provided value and blinding.
            // This either means that the commitment does not correspond to the shared
            // secret, or that the amount is malformed (and is probably not
            // spendable).
            return Err(AmountError::InconsistentCommitment);
        }

        Ok((amount, blinding))
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
    /// * MaskedAmount
    /// * Amount (token id and value)
    /// or
    /// * An amount error
    pub fn reconstruct(
        masked_value: u64,
        masked_token_id: &[u8],
        tx_out_shared_secret: &RistrettoPublic,
    ) -> Result<(Self, Amount), AmountError> {
        let (expected_commitment, amount, _) =
            Self::compute_commitment(masked_value, masked_token_id, tx_out_shared_secret)?;

        let result = Self {
            commitment: expected_commitment,
            masked_value,
            masked_token_id: masked_token_id.to_vec(),
        };

        Ok((result, amount))
    }

    /// Compute the expected commitment corresponding to a masked value, masked
    /// token id, and shared secret, returning errors if the masked token id
    /// is malformed.
    fn compute_commitment(
        masked_value: u64,
        masked_token_id: &[u8],
        tx_out_shared_secret: &RistrettoPublic,
    ) -> Result<(CompressedCommitment, Amount, Scalar), AmountError> {
        let token_id = TokenId::from(Self::unmask_token_id(
            masked_token_id,
            tx_out_shared_secret,
        )?);
        let value: u64 = Self::unmask_value(masked_value, tx_out_shared_secret);
        let blinding = get_blinding(tx_out_shared_secret);

        // Pedersen generators
        let generator = generators(*token_id);

        let expected_commitment = CompressedCommitment::new(value, blinding, &generator);

        Ok((expected_commitment, Amount { value, token_id }, blinding))
    }

    fn compute_commitment_crc32(commitment: &CompressedCommitment) -> u32 {
        Crc::<u32>::new(&crc::CRC_32_ISO_HDLC).checksum(commitment.point.as_bytes())
    }

    /// Reveals `masked_value`.
    fn unmask_value(masked_value: u64, tx_out_shared_secret: &RistrettoPublic) -> u64 {
        masked_value ^ get_value_mask(tx_out_shared_secret)
    }

    /// Reveals `masked_token_id`, with backwards compat
    fn unmask_token_id(
        masked_token_id: &[u8],
        tx_out_shared_secret: &RistrettoPublic,
    ) -> Result<u64, AmountError> {
        match masked_token_id.len() {
            0 => Ok(0),
            TokenId::NUM_BYTES => {
                // Safety: We just checked masked_token_id.len() == TokenId::NUM_BYTES
                let masked_token_id_val = u64::from_le_bytes(masked_token_id.try_into().unwrap());
                Ok(masked_token_id_val ^ get_token_id_mask(tx_out_shared_secret))
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
    hasher.update(AMOUNT_VALUE_DOMAIN_TAG);
    hasher.update(shared_secret.to_bytes());
    let scalar = Scalar::from_hash(hasher);
    let mut temp = [0u8; 8];
    temp.copy_from_slice(&scalar.as_bytes()[0..8]);
    u64::from_le_bytes(temp)
}

/// Computes `Blake2B(token_id_mask | shared_secret)`,
/// then interprets the first 8 canonical bytes as a u64 number in
/// little-endian representation.
///
/// # Arguments
/// * `shared_secret` - The shared secret, e.g. `rB`.
fn get_token_id_mask(shared_secret: &RistrettoPublic) -> u64 {
    let mut hasher = Blake2b512::new();
    hasher.update(AMOUNT_TOKEN_ID_DOMAIN_TAG);
    hasher.update(shared_secret.to_bytes());
    u64::from_le_bytes(hasher.finalize()[0..8].try_into().unwrap())
}

/// Computes `Blake2B("blinding" | shared_secret)`.
///
/// # Arguments
/// * `shared_secret` - The shared secret, e.g. `rB`.
fn get_blinding(shared_secret: &RistrettoPublic) -> Scalar {
    let mut hasher = Blake2b512::new();
    hasher.update(AMOUNT_BLINDING_DOMAIN_TAG);
    hasher.update(shared_secret.to_bytes());
    Scalar::from_hash(hasher)
}

#[cfg(test)]
mod amount_tests {
    #![allow(clippy::unnecessary_operation)]

    use super::*;
    use crate::proptest_fixtures::*;
    use mc_crypto_ring_signature::{generators, CompressedCommitment};
    use proptest::prelude::*;

    proptest! {
        #[test]
        /// MaskedAmount::new() should return Ok for valid values and blindings.
        fn test_new_ok(
            value in any::<u64>(),
            token_id in any::<u64>(),
            shared_secret in arbitrary_ristretto_public()) {
                let amount = Amount { value, token_id: token_id.into() };
            assert!(MaskedAmountV1::new(amount, &shared_secret).is_ok());
        }

        #[test]
        #[allow(non_snake_case)]
        /// amount.commitment should agree with the value and blinding.
        fn test_commitment(
            value in any::<u64>(),
            token_id in any::<u64>(),
            shared_secret in arbitrary_ristretto_public()) {
                let amount = Amount { value, token_id: token_id.into() };
                let amount = MaskedAmountV1::new(amount, &shared_secret).unwrap();
                let blinding = get_blinding(&shared_secret);
                let expected_commitment = CompressedCommitment::new(value, blinding, &generators(token_id));
                assert_eq!(amount.commitment, expected_commitment);
        }

        #[test]
        /// amount.unmask_value should return the value used to construct the amount.
        fn test_unmask_value(
            value in any::<u64>(),
            token_id in any::<u64>(),
            shared_secret in arbitrary_ristretto_public())
        {
            let amount = Amount { value, token_id: token_id.into() };
            let masked_amount = MaskedAmountV1::new(amount, &shared_secret).unwrap();
            assert_eq!(
                value,
                MaskedAmountV1::unmask_value(masked_amount.masked_value, &shared_secret)
            );
        }

        #[test]
        /// get_value should return the correct value and blinding.
        fn test_get_value_ok(
            value in any::<u64>(),
            token_id in any::<u64>(),
            shared_secret in arbitrary_ristretto_public()) {
            let amount = Amount { value, token_id: token_id.into() };
            let masked_amount = MaskedAmountV1::new(amount, &shared_secret).unwrap();
            let result = masked_amount.get_value(&shared_secret);
            let blinding = get_blinding(&shared_secret);
            let expected = Ok((amount, blinding));
            assert_eq!(result, expected);
        }


        #[test]
        /// get_value should return InconsistentCommitment if the masked value is incorrect.
        fn test_get_value_incorrect_masked_value(
            value in any::<u64>(),
            token_id in any::<u64>(),
            other_masked_value in any::<u64>(),
            shared_secret in arbitrary_ristretto_public())
        {
            // Mutate amount to use a different masked value.
            // With high probability, amount.masked_value won't equal other_masked_value.
            let amount = Amount { value, token_id: token_id.into() };
            let mut masked_amount = MaskedAmountV1::new(amount, &shared_secret).unwrap();
            masked_amount.masked_value = other_masked_value;
            let result = masked_amount.get_value(&shared_secret);
            let expected = Err(AmountError::InconsistentCommitment);
            assert_eq!(result, expected);
        }

        #[test]
        /// get_value should return an Error if shared_secret is incorrect.
        fn test_get_value_invalid_shared_secret(
            value in any::<u64>(),
            token_id in any::<u64>(),
            shared_secret in arbitrary_ristretto_public(),
            other_shared_secret in arbitrary_ristretto_public(),
        ) {
            let amount = Amount { value, token_id: token_id.into() };
            let masked_amount = MaskedAmountV1::new(amount,  &shared_secret).unwrap();
            let result = masked_amount.get_value(&other_shared_secret);
            let expected = Err(AmountError::InconsistentCommitment);
            assert_eq!(result, expected);
        }

        #[test]
        /// test the length when this Amount is serialized
        fn test_serialization_length(
            value in any::<u64>(),
            token_id in any::<u64>(),
            shared_secret in arbitrary_ristretto_public()
        ) {
            let amount = Amount { value, token_id: token_id.into() };
            let masked_amount = MaskedAmountV1::new(amount, &shared_secret).unwrap();
            let buf = masked_amount.encode_to_vec();
            assert_eq!(buf.len(), 55);
        }
    }
}
