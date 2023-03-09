// Copyright (c) 2018-2023 The MobileCoin Foundation

//! A signed contingent input as described in MCIP #31

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use displaydoc::Display;
use mc_crypto_digestible::Digestible;
use mc_crypto_ring_signature::{
    Commitment, CompressedCommitment, CurveScalar, Error as RingSignatureError, KeyImage, RingMLSAG,
};
use mc_transaction_core::{
    ring_ct::{GeneratorCache, OutputSecret, PresignedInputRing, SignedInputRing},
    tx::TxIn,
    Amount, AmountError, RevealedTxOutError, TokenId, TxOutConversionError,
};
use mc_util_u64_ratio::U64Ratio;
use prost::Message;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// The "unmasked" data of an amount commitment
#[derive(Clone, Deserialize, Digestible, Eq, Message, PartialEq, Serialize, Zeroize)]
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
#[derive(Clone, Deserialize, Digestible, Eq, Message, PartialEq, Serialize, Zeroize)]
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
    pub fn validate(&self) -> Result<SignedContingentInputAmounts, SignedContingentInputError> {
        if self.tx_out_global_indices.len() != self.tx_in.ring.len() {
            return Err(SignedContingentInputError::WrongNumberOfGlobalIndices);
        }

        let mut result = SignedContingentInputAmounts {
            pseudo_output: (&self.pseudo_output_amount).into(),
            ..Default::default()
        };

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

            // Check that required outputs match their claimed amounts
            for (amount, output) in self
                .required_output_amounts
                .iter()
                .zip(rules.required_outputs.iter())
            {
                result.required_outputs.push(Amount::from(amount));
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

            // Check that partial fill rule specs look correct
            if let Some(partial_fill_change) = rules.partial_fill_change.as_ref() {
                let (amount, _) = partial_fill_change.reveal_amount()?;
                // If the min fill value exceeds the fractional change, the SCI is ill-formed
                if rules.min_partial_fill_value > amount.value {
                    return Err(
                        SignedContingentInputError::MinPartialFillValueExceedsPartialChange,
                    );
                }

                if amount.value == 0 {
                    return Err(SignedContingentInputError::ZeroPartialFillChange);
                }

                result.partial_fill_change = Some(amount);

                // Check that each output can actually be revealed
                for partial_fill_output in rules.partial_fill_outputs.iter() {
                    let (amount, _) = partial_fill_output.reveal_amount()?;
                    if amount.value == 0 {
                        return Err(SignedContingentInputError::ZeroPartialFillOutput);
                    }
                    result.partial_fill_outputs.push(amount);
                }
            } else if !rules.partial_fill_outputs.is_empty() || rules.min_partial_fill_value != 0 {
                return Err(SignedContingentInputError::MissingPartialFillChange);
            }
        }

        Ok(result)
    }
}

/// This summary object is constructed during validation of an SCI, by recording
/// all the Amount objects that we successfully unmask.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignedContingentInputAmounts {
    /// The amount of the pseudo-output, i.e. the true input signed over in this
    /// SCI
    pub pseudo_output: Amount,
    /// The amounts of the required outputs
    pub required_outputs: Vec<Amount>,
    /// The amounts of the partial fill outputs.
    pub partial_fill_outputs: Vec<Amount>,
    /// The amount of hte partial fill change if present.
    pub partial_fill_change: Option<Amount>,
}

impl SignedContingentInputAmounts {
    /// Computes the hypothetical change in balances that will occur if we fill
    /// this SCI to a certain degree
    ///
    /// Add the outputs and inputs to a BTreemap which functions as a balance
    /// sheet. Outputs from the SCI are positive, and the value of the input
    /// is negative.
    ///
    /// Arguments:
    /// partial_fill_value: The amount of the partial_fill_change we want to
    /// keep. This should be zero if this is not a partial fill SCI.
    /// balance_sheet: A list of tokens and +/- balance changes
    ///
    /// Returns:
    /// An error if the partial fill value is too large for this SCI, or
    /// something else is ill-formed.
    pub fn add_to_balance_sheet(
        &self,
        partial_fill_value: u64,
        balance_sheet: &mut BTreeMap<TokenId, i128>,
    ) -> Result<(), SignedContingentInputError> {
        // The pseudo-output amount (the value of the input which was signed over) is
        // subtracted from balance sheet, everything else is added
        *balance_sheet
            .entry(self.pseudo_output.token_id)
            .or_default() -= self.pseudo_output.value as i128;

        // Required amount are added in full
        for req_output in self.required_outputs.iter() {
            *balance_sheet.entry(req_output.token_id).or_default() += req_output.value as i128;
        }

        if let Some(partial_fill_change) = self.partial_fill_change.as_ref() {
            // Compute fill fraction
            let fill_fraction = U64Ratio::new(partial_fill_value, partial_fill_change.value)
                .ok_or(SignedContingentInputError::ZeroPartialFillChange)?;

            // Compute value of fractional change output and add to balance sheet
            let fractional_change_value = partial_fill_change
                .value
                .checked_sub(partial_fill_value)
                .ok_or(SignedContingentInputError::PartialFillValueTooLarge)?;
            *balance_sheet
                .entry(partial_fill_change.token_id)
                .or_default() += fractional_change_value as i128;

            // Compute value of each fractional output and add to balance sheet
            for partial_fill_output in self.partial_fill_outputs.iter() {
                let fractional_output_value = fill_fraction
                    .checked_mul_round_up(partial_fill_output.value)
                    .ok_or(SignedContingentInputError::PartialFillValueTooLarge)?;
                *balance_sheet
                    .entry(partial_fill_output.token_id)
                    .or_default() += fractional_output_value as i128;
            }
        } else if partial_fill_value != 0 {
            return Err(SignedContingentInputError::PartialFillValueTooLarge);
        }
        Ok(())
    }

    /// Compute the balance sheet just for this SCI.
    pub fn compute_balance_sheet(
        &self,
        partial_fill_value: u64,
    ) -> Result<BTreeMap<TokenId, i128>, SignedContingentInputError> {
        let mut result = Default::default();
        self.add_to_balance_sheet(partial_fill_value, &mut result)?;
        Ok(result)
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
#[derive(Clone, Debug, Deserialize, Display, Eq, PartialEq, Serialize)]
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
    /// Partial fill input not allowed with this API
    PartialFillInputNotAllowedHere,
    /// Missing partial fill change output
    MissingPartialFillChange,
    /// Index out of bounds
    IndexOutOfBounds,
    /// Partial fill change amount was zero
    ZeroPartialFillChange,
    /// Partial fill output amount was zero
    ZeroPartialFillOutput,
    /// Min partial fill value exceeds partial fill change
    MinPartialFillValueExceedsPartialChange,
    /// Token id mismatch
    TokenIdMismatch,
    /// Change value exceeded limit imposed by input rules
    ChangeLimitExceeded,
    /// Revealing TxOut: {0}
    RevealedTxOut(RevealedTxOutError),
    /// Feature is not supported at this block version ({0}): {1}
    FeatureNotSupportedAtBlockVersion(u32, String),
    /// Block version mismatch: {0} vs. {1}
    BlockVersionMismatch(u32, u32),
    /// Amount: {0}
    Amount(AmountError),
    /// Partial fill Value is too large compared to partial fill change
    PartialFillValueTooLarge,
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

impl From<RevealedTxOutError> for SignedContingentInputError {
    fn from(src: RevealedTxOutError) -> Self {
        Self::RevealedTxOut(src)
    }
}

impl From<AmountError> for SignedContingentInputError {
    fn from(src: AmountError) -> Self {
        Self::Amount(src)
    }
}
