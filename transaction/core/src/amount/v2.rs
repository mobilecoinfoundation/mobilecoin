// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A commitment to an output's amount, denominated in picoMOB.
//!
//! Amounts are implemented as Pedersen commitments. The associated private keys
//! are "masked" using a shared secret.

use crate::{
    domain_separators::{
        AMOUNT_BLINDING_DOMAIN_TAG, AMOUNT_BLINDING_FACTORS_DOMAIN_TAG,
        AMOUNT_SHARED_SECRET_DOMAIN_TAG, AMOUNT_TOKEN_ID_DOMAIN_TAG, AMOUNT_VALUE_DOMAIN_TAG,
    },
    Amount, AmountError, TokenId,
};
use alloc::vec::Vec;
use core::convert::TryInto;
use crc::Crc;
use hkdf::Hkdf;
use mc_crypto_digestible::Digestible;
use mc_crypto_hashes::Digest;
use mc_crypto_keys::RistrettoPublic;
use mc_crypto_ring_signature::{generators, CompressedCommitment, Scalar};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zeroize::Zeroize;

/// A commitment to an amount of MobileCoin or a related token, as it appears on
/// the blockchain. This is a "blinded" commitment, and only the sender and
/// receiver know the value and token id.
///
/// This differs from MaskedAmountV1 in that there is an "amount shared secret"
/// which is computed by hashing from "tx out shared secret". The purpose of
/// this is to make it possible to selectively reveal the amount and token id of
/// a TxOut, without revealing the memo and other things. (See also MCIP #42).
#[derive(Clone, Deserialize, Digestible, Eq, Hash, Message, PartialEq, Serialize, Zeroize)]
pub struct MaskedAmountV2 {
    /// A Pedersen commitment `v*H + b*G` to a quantity `v` of MobileCoin or a
    /// related token, with blinding `b`,
    #[prost(message, required, tag = "1")]
    pub commitment: CompressedCommitment,

    /// `masked_value = value XOR_8 Blake2B(value_mask | shared_secret)`
    #[prost(fixed64, required, tag = "2")]
    pub masked_value: u64,

    /// `masked_token_id = token_id XOR_8 Blake2B(token_id_mask |
    /// shared_secret)` 8 bytes long when used, 0 bytes for older amounts
    /// that don't have this.
    #[prost(bytes, tag = "3")]
    pub masked_token_id: Vec<u8>,
}

impl MaskedAmountV2 {
    /// Creates a commitment `value*H + blinding*G`, and "masks" the commitment
    /// secrets so that they can be recovered by the recipient.
    ///
    /// # Arguments
    /// * `amount` - The amount information to be masked
    /// * `shared_secret` - The shared secret, e.g. `rB` for transaction private
    ///   key `r` and recipient public key `B`.
    #[inline]
    pub fn new(
        amount: Amount,
        tx_out_shared_secret: &RistrettoPublic,
    ) -> Result<Self, AmountError> {
        let amount_shared_secret = Self::compute_amount_shared_secret(tx_out_shared_secret);
        Self::new_from_amount_shared_secret(amount, &amount_shared_secret)
    }

    /// Create a new masked amount from an amount and an amount shared secret
    pub fn new_from_amount_shared_secret(
        amount: Amount,
        amount_shared_secret: &[u8; 32],
    ) -> Result<Self, AmountError> {
        let (value_mask, token_id_mask, blinding) = get_blinding_factors(amount_shared_secret);

        // Pedersen generators
        let generator = generators(*amount.token_id);

        // Pedersen commitment `v*H_i + b*G`.
        let commitment = CompressedCommitment::new(amount.value, blinding, &generator);

        // The value is XORed with the 8 bytes of the mask.
        let masked_value: u64 = amount.value ^ value_mask;

        // The token_id is XORed with the 8 bytes of the mask.
        let masked_token_id_val: u64 = *amount.token_id ^ token_id_mask;
        let masked_token_id = masked_token_id_val.to_le_bytes().to_vec();

        Ok(Self {
            commitment,
            masked_value,
            masked_token_id,
        })
    }

    /// Returns the amount underlying the masked amount, given the shared
    /// secret.
    ///
    /// Value is denominated in smallest representable units (e.g. "picoMOB").
    ///
    /// # Arguments
    /// * `tx_out_shared_secret` - The shared secret, e.g. `rB`.
    pub fn get_value(
        &self,
        tx_out_shared_secret: &RistrettoPublic,
    ) -> Result<(Amount, Scalar), AmountError> {
        let amount_shared_secret = Self::compute_amount_shared_secret(tx_out_shared_secret);
        self.get_value_from_amount_shared_secret(&amount_shared_secret)
    }

    /// Get the amount shared secret from the tx out shared secret
    pub fn compute_amount_shared_secret(tx_out_shared_secret: &RistrettoPublic) -> [u8; 32] {
        let mut hasher = Sha512::new();
        hasher.update(&AMOUNT_SHARED_SECRET_DOMAIN_TAG);
        hasher.update(&tx_out_shared_secret.to_bytes());
        // Safety: Sha512 is a 512-bit (64-byte) hash.
        hasher.finalize()[0..32].try_into().unwrap()
    }

    /// Returns the amount underlying the masked amount, given the amount shared
    /// secret.
    ///
    /// Generally, the recipient knows the TxOut shared secret, and it's more
    /// convenient to use [get_value()]. This function allows that the sender or
    /// recipient could selectively disclose the `amount_shared_secret` to a
    /// third party who can then use this function to audit the value of
    /// a TxOut without having permissions to do other things that require the
    /// TxOut shared secret.
    ///
    /// # Arguments
    /// * `amount_shared_secret` - The shared secret, derived by hashing TxOut
    ///   shared secret
    pub fn get_value_from_amount_shared_secret(
        &self,
        amount_shared_secret: &[u8; 32],
    ) -> Result<(Amount, Scalar), AmountError> {
        let (expected_commitment, amount, blinding) = Self::compute_commitment(
            self.masked_value,
            &self.masked_token_id,
            amount_shared_secret,
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
        let amount_shared_secret = Self::compute_amount_shared_secret(tx_out_shared_secret);

        let (expected_commitment, amount, _) =
            Self::compute_commitment(masked_value, masked_token_id, &amount_shared_secret)?;

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
        amount_shared_secret: &[u8; 32],
    ) -> Result<(CompressedCommitment, Amount, Scalar), AmountError> {
        let (value_mask, token_id_mask, blinding) = get_blinding_factors(amount_shared_secret);

        // Note: Empty masked_token_id defaults to zero only in v1, not in v2, since v2
        // masked amounts were never created without masked token id.
        let token_id = TokenId::from(match masked_token_id.len() {
            TokenId::NUM_BYTES => {
                // Safety: We just checked masked_token_id.len() == TokenId::NUM_BYTES
                u64::from_le_bytes(masked_token_id.try_into().unwrap()) ^ token_id_mask
            }
            _ => return Err(AmountError::InvalidMaskedTokenId),
        });

        let value = masked_value ^ value_mask;

        // Pedersen generators
        let generator = generators(*token_id);

        let expected_commitment = CompressedCommitment::new(value, blinding, &generator);

        Ok((expected_commitment, Amount { value, token_id }, blinding))
    }

    fn compute_commitment_crc32(commitment: &CompressedCommitment) -> u32 {
        Crc::<u32>::new(&crc::CRC_32_ISO_HDLC).checksum(commitment.point.as_bytes())
    }
}

/// Computes the value mask, token id mask, and blinding factor for the
/// commitment, in a masked amount.
///
/// # Arguments
/// * `amount_shared_secret` - The amount shared secret, derived as a hash of
///   `rB`.
fn get_blinding_factors(amount_shared_secret: &[u8; 32]) -> (u64, u64, Scalar) {
    // Use HKDF-SHA512 to produce blinding factors for value, token id, and
    // commitment
    let kdf = Hkdf::<Sha512>::new(
        Some(AMOUNT_BLINDING_FACTORS_DOMAIN_TAG),
        amount_shared_secret,
    );

    let mut value_mask = [0u8; 8];
    kdf.expand(AMOUNT_VALUE_DOMAIN_TAG.as_bytes(), &mut value_mask)
        .expect("Digest output size is insufficient");

    let mut token_id_mask = [0u8; 8];
    kdf.expand(AMOUNT_TOKEN_ID_DOMAIN_TAG.as_bytes(), &mut token_id_mask)
        .expect("Digest output size is insufficient");

    let mut scalar_blinding_bytes = [0u8; 64];
    kdf.expand(
        AMOUNT_BLINDING_DOMAIN_TAG.as_bytes(),
        &mut scalar_blinding_bytes,
    )
    .expect("Digest output size is insufficient");

    (
        u64::from_le_bytes(value_mask),
        u64::from_le_bytes(token_id_mask),
        Scalar::from_bytes_mod_order_wide(&scalar_blinding_bytes),
    )
}

#[cfg(test)]
mod amount_tests {
    #![allow(clippy::unnecessary_operation)]

    use super::*;
    use crate::{proptest_fixtures::*, ring_signature::generators, CompressedCommitment};
    use proptest::prelude::*;

    proptest! {
        #[test]
        /// MaskedAmount::new() should return Ok for valid values and blindings.
        fn test_new_ok(
            value in any::<u64>(),
            token_id in any::<u64>(),
            tx_out_shared_secret in arbitrary_ristretto_public()) {
                let amount = Amount { value, token_id: token_id.into() };
             assert!(MaskedAmountV2::new(amount, &tx_out_shared_secret).is_ok());
        }

        #[test]
        #[allow(non_snake_case)]
        /// amount.commitment should agree with the value and blinding.
        fn test_commitment(
            value in any::<u64>(),
            token_id in any::<u64>(),
            tx_out_shared_secret in arbitrary_ristretto_public()) {
                let amount = Amount { value, token_id: token_id.into() };
                let amount = MaskedAmountV2::new(amount, &tx_out_shared_secret).unwrap();

                let amount_shared_secret = MaskedAmountV2::compute_amount_shared_secret(&tx_out_shared_secret);
                let (_, _, blinding) = get_blinding_factors(&amount_shared_secret);
                let expected_commitment = CompressedCommitment::new(value, blinding, &generators(token_id));
                assert_eq!(amount.commitment, expected_commitment);
        }

        #[test]
        /// get_value should return the correct value and blinding.
        fn test_get_value_ok(
            value in any::<u64>(),
            token_id in any::<u64>(),
            tx_out_shared_secret in arbitrary_ristretto_public()) {
            let amount = Amount { value, token_id: token_id.into() };
            let masked_amount = MaskedAmountV2::new(amount, &tx_out_shared_secret).unwrap();
            let result = masked_amount.get_value(&tx_out_shared_secret);

                let amount_shared_secret = MaskedAmountV2::compute_amount_shared_secret(&tx_out_shared_secret);
                let (_, _, blinding) = get_blinding_factors(&amount_shared_secret);
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
            let mut masked_amount = MaskedAmountV2::new(amount, &shared_secret).unwrap();
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
            let masked_amount = MaskedAmountV2::new(amount,  &shared_secret).unwrap();
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
            let masked_amount = MaskedAmountV2::new(amount, &shared_secret).unwrap();
            let buf = masked_amount.encode_to_vec();
            assert_eq!(buf.len(), 55);
        }
    }
}
