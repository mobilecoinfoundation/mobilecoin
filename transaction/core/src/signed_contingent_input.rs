// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A signed contingent input as described in MCIP #31

use crate::{
    ring_ct::{GeneratorCache, OutputSecret, PresignedInputRing, SignedInputRing},
    tx::TxIn,
    Amount, TokenId, TxOutConversionError,
};
use alloc::vec::Vec;
use displaydoc::Display;
use mc_crypto_ring_signature::{
    Commitment, CompressedCommitment, CurveScalar, Error as RingSignatureError, KeyImage, RingMLSAG,
};
use prost::Message;

/// The "unmasked" data of an amount commitment
#[derive(Clone, Eq, Message, PartialEq)]
pub struct UnmaskedAmount {
    /// The value of the amount commitment
    #[prost(fixed64, tag = 1)]
    pub value: u64,

    /// The token id of the amount commitment
    #[prost(fixed64, tag = 2)]
    pub token_id: u64,

    /// The blinding factor of the amount commitment
    #[prost(message, required, tag = 3)]
    pub blinding: CurveScalar,
}

/// A signed contingent input is a "transaction fragment" which can be
/// incorporated into a transaction signed by a counterparty. See MCIP #31 for
/// motivation.
#[derive(Clone, Eq, Message, PartialEq)]
pub struct SignedContingentInput {
    /// The block version rules we used when making the signature
    #[prost(uint32, required, tag = 1)]
    pub block_version: u32,

    /// The tx_in which was signed over
    #[prost(message, required, tag = 2)]
    pub tx_in: TxIn,

    /// The Ring MLSAG signature, conferring spending authority
    #[prost(message, required, tag = 3)]
    pub mlsag: RingMLSAG,

    /// The amount and blinding of the pseudo-output of the MLSAG
    #[prost(message, required, tag = 4)]
    pub pseudo_output_amount: UnmaskedAmount,

    /// The amount and blinding of any TxOut required by the input rules
    #[prost(message, repeated, tag = 5)]
    pub required_output_amounts: Vec<UnmaskedAmount>,

    /// The tx_out global index of each ring member
    /// This helps the recipient of this payload construct proofs of membership
    /// for the ring
    #[prost(fixed64, repeated, tag = 6)]
    pub tx_out_global_indices: Vec<u64>,
}

impl SignedContingentInput {
    /// The key image of the input which has been signed. If this key image
    /// appears already in the ledger, then the signed contingent input is
    /// no longer valid.
    pub fn key_image(&self) -> KeyImage {
        self.mlsag.key_image
    }

    /// Validation checks that a signed contingent input is well-formed.
    ///
    /// * The ring MLSAG actually signs the pseudo-output as claimed
    /// * The required output amounts actually correspond to the required
    ///   outputs
    ///
    /// Note: This does check any other rules like tombstone block, or
    /// confirm proofs of membership, which are normally added only when this
    /// is incorporated into a transaction
    pub fn validate(&self) -> Result<(), SignedContingentInputError> {
        if self.tx_out_global_indices.len() != self.tx_in.ring.len() {
            return Err(SignedContingentInputError::WrongNumberOfGlobalIndices);
        }

        let mut generator_cache = GeneratorCache::default();
        let generator = generator_cache.get(TokenId::from(self.pseudo_output_amount.token_id));

        let pseudo_output = CompressedCommitment::from(&Commitment::new(
            self.pseudo_output_amount.value,
            self.pseudo_output_amount.blinding.into(),
            generator,
        ));

        let rules_digest = self
            .tx_in
            .signed_digest()
            .ok_or(SignedContingentInputError::MissingRules)?;

        let signed_input_ring = SignedInputRing::try_from(&self.tx_in)?;

        self.mlsag
            .verify(&rules_digest, &signed_input_ring.members, &pseudo_output)?;

        if let Some(rules) = &self.tx_in.input_rules {
            if self.required_output_amounts.len() != rules.required_outputs.len() {
                return Err(SignedContingentInputError::WrongNumberOfRequiredOutputAmounts);
            }

            for (amount, output) in self
                .required_output_amounts
                .iter()
                .zip(rules.required_outputs.iter())
            {
                let generator = generator_cache.get(TokenId::from(amount.token_id));

                let expected_commitment = CompressedCommitment::from(&Commitment::new(
                    amount.value,
                    amount.blinding.into(),
                    generator,
                ));
                if &expected_commitment != output.get_masked_amount()?.commitment() {
                    return Err(SignedContingentInputError::RequiredOutputMismatch);
                }
            }
        }

        Ok(())
    }
}

impl From<SignedContingentInput> for PresignedInputRing {
    fn from(src: SignedContingentInput) -> Self {
        Self {
            mlsag: src.mlsag,
            pseudo_output_secret: src.pseudo_output_amount.into(),
        }
    }
}

impl From<UnmaskedAmount> for OutputSecret {
    fn from(src: UnmaskedAmount) -> Self {
        Self {
            amount: Amount::new(src.value, src.token_id.into()),
            blinding: src.blinding.into(),
        }
    }
}

impl From<OutputSecret> for UnmaskedAmount {
    fn from(src: OutputSecret) -> Self {
        Self {
            value: src.amount.value,
            token_id: *src.amount.token_id,
            blinding: src.blinding.into(),
        }
    }
}

impl From<&UnmaskedAmount> for Amount {
    fn from(src: &UnmaskedAmount) -> Self {
        Self {
            value: src.value,
            token_id: TokenId::from(src.token_id),
        }
    }
}

/// An error which can occur when validating a signed contingent input
#[derive(Display, Debug, Clone)]
pub enum SignedContingentInputError {
    /// The number of required outputs did not match to the number of amounts
    WrongNumberOfRequiredOutputAmounts,
    /// The number of global indices did not match the number of inputs
    WrongNumberOfGlobalIndices,
    /// The amount of a required output was incorrect
    RequiredOutputMismatch,
    /// Input rules are missing
    MissingRules,
    /// Proofs of membership are missing
    MissingProofs,
    /// Invalid Ring signature: {0}
    RingSignature(RingSignatureError),
    /// TxOut conversion: {0}
    TxOutConversion(TxOutConversionError),
}

impl From<RingSignatureError> for SignedContingentInputError {
    fn from(src: RingSignatureError) -> Self {
        Self::RingSignature(src)
    }
}

impl From<TxOutConversionError> for SignedContingentInputError {
    fn from(src: TxOutConversionError) -> Self {
        Self::TxOutConversion(src)
    }
}
