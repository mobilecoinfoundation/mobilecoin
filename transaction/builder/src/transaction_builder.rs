// Copyright (c) 2018-2024 The MobileCoin Foundation

//! Utility for building and signing a transaction.
//!
//! See https://cryptonote.org/img/cryptonote_transaction.png

use crate::{
    input_materials::InputMaterials, InputCredentials, MemoBuilder, ReservedSubaddresses,
    TxBlueprint, TxBlueprintOutput, TxBuilderError,
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    cmp::{min, Ordering},
    fmt::Debug,
};
use mc_account_keys::PublicAddress;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature_signer::RingSigner;
use mc_fog_report_validation::FogPubkeyResolver;
use mc_transaction_core::{
    encrypted_fog_hint::EncryptedFogHint,
    fog_hint::FogHint,
    onetime_keys::{create_shared_secret, create_tx_out_public_key},
    ring_ct::{InputRing, OutputSecret},
    ring_signature::Scalar,
    tokens::Mob,
    tx::{Tx, TxIn, TxOut},
    Amount, BlockVersion, FeeMap, MemoContext, MemoPayload, NewMemoError, RevealedTxOut,
    RevealedTxOutError, Token, TokenId,
};
use mc_transaction_extra::{
    SignedContingentInput, SignedContingentInputError, TxOutConfirmationNumber, UnsignedTx,
};
use mc_util_from_random::FromRandom;
use mc_util_u64_ratio::U64Ratio;
use rand_core::{CryptoRng, RngCore};

/// A trait used to compare the transaction outputs
pub trait TxOutputsOrdering {
    /// comparer method
    fn cmp(a: &CompressedRistrettoPublic, b: &CompressedRistrettoPublic) -> Ordering;
}

/// Default implementation for transaction outputs
pub struct DefaultTxOutputsOrdering;

impl TxOutputsOrdering for DefaultTxOutputsOrdering {
    fn cmp(a: &CompressedRistrettoPublic, b: &CompressedRistrettoPublic) -> Ordering {
        a.cmp(b)
    }
}

/// Transaction output context is produced by add_output method
/// Used for receipt creation
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxOutContext {
    /// TxOut public key that comes from a transaction builder
    /// add_output/add_change_output
    pub tx_out_public_key: CompressedRistrettoPublic,
    /// confirmation that comes from a transaction builder
    /// add_output/add_change_output
    pub confirmation: TxOutConfirmationNumber,
    /// Shared Secret that comes from a transaction builder
    /// add_output/add_change_output
    pub shared_secret: RistrettoPublic,
}

/// Helper utility for building and signing a CryptoNote-style transaction,
/// and attaching fog hint and memos as appropriate.
///
/// This is generic over FogPubkeyResolver because there are several reasonable
/// implementations of that.
///
/// This is generic over MemoBuilder to allow injecting a policy for how to
/// use the memos in the TxOuts.
#[derive(Clone, Debug)]
pub struct TransactionBuilder<FPR: FogPubkeyResolver> {
    /// The block version that we are targeting for this transaction
    block_version: BlockVersion,
    /// The input materials used to form the transaction.
    input_materials: Vec<InputMaterials>,
    /// The outputs that we will produce when going from a `TxBlueprint` to an
    /// `UnsignedTx`.
    outputs: Vec<TxBlueprintOutput>,
    /// The tombstone_block value, a block index in which the transaction
    /// expires, and can no longer be added to the blockchain
    tombstone_block: u64,
    /// The fee paid in connection to this transaction
    /// If mixed transactions feature is off, then everything must be this token
    /// id.
    fee: Amount,
    /// The source of validated fog pubkeys used for this transaction
    fog_resolver: Arc<FPR>,
    /// The limit on the tombstone block value imposed pubkey_expiry values in
    /// fog pubkeys used so far
    fog_tombstone_block_limit: u64,
    /// The minimum fee map, if available.
    fee_map: Option<FeeMap>,
}

impl<FPR: FogPubkeyResolver> TransactionBuilder<FPR> {
    /// Initializes a new TransactionBuilder.
    ///
    /// # Arguments
    /// * `block_version` - The block version rules to use when building this
    ///   transaction
    /// * `fee` - The fee (and token id) to use for this transaction. Note: The
    ///   fee token id cannot be changed later, and before mixed transactions
    ///   feature, every input and output must have the same token id as the
    ///   fee.
    /// * `fog_resolver` - Source of validated fog keys to use with this
    ///   transaction
    pub fn new(
        block_version: BlockVersion,
        fee: Amount,
        fog_resolver: FPR,
    ) -> Result<Self, TxBuilderError> {
        Ok(Self {
            block_version,
            fee,
            fee_map: None,
            fog_resolver: Arc::new(fog_resolver),
            fog_tombstone_block_limit: u64::MAX,
            input_materials: Vec::new(),
            outputs: Vec::new(),
            tombstone_block: u64::MAX,
        })
    }

    /// Add an Input to the transaction.
    ///
    /// # Arguments
    /// * `input_credentials` - Credentials required to construct a ring
    ///   signature for an input.
    pub fn add_input(&mut self, input_credentials: InputCredentials) {
        self.input_materials
            .push(InputMaterials::Signable(input_credentials));
    }

    /// Add a pre-signed Input to the transaction, also fulfilling any
    /// requirements imposed by the signed rules, so that our transaction
    /// will be valid.
    ///
    /// Note: Before adding a signed_contingent_input, you probably want to:
    /// * validate it (call .validate())
    /// * check if key image appeared already (call .key_image())
    /// * provide merkle proofs of membership for each ring member (see
    ///   .tx_out_global_indices)
    ///
    /// # Arguments
    /// * `signed_contingent_input` - The pre-signed input we are adding
    pub fn add_presigned_input(
        &mut self,
        sci: SignedContingentInput,
    ) -> Result<(), SignedContingentInputError> {
        if let Some(rules) = sci.tx_in.input_rules.as_ref() {
            // Check for any partial fill elements. These cannot be used with this API,
            // the caller must use add_presigned_partial_fill_input instead.
            if rules.partial_fill_change.is_some()
                || !rules.partial_fill_outputs.is_empty()
                || rules.min_partial_fill_value != 0
            {
                return Err(SignedContingentInputError::PartialFillInputNotAllowedHere);
            }
        }

        self.add_presigned_input_helper(sci)
    }

    /// Add a pre-signed Input with partial fill rules to the transaction, also
    /// fulfilling any requirements imposed by the signed rules, so that our
    /// transaction will be valid.
    ///
    /// Note: Before adding a signed_contingent_input, you probably want to:
    /// * validate it (call .validate())
    /// * check if key image appeared already (call .key_image())
    /// * provide merkle proofs of membership for each ring member (see
    ///   .tx_out_global_indices)
    ///
    /// # Arguments
    /// * `signed_contingent_input` - The pre-signed input we are adding
    /// * `sci_change_amount` - The amount of value of the SCI which we are
    ///   returning to the signer. This determines the "fill fraction" for the
    ///   partial-fill rules. This will be equal to the
    ///   real_change_output_amount.
    ///
    /// # Returns
    /// * A list of all outlay amounts deduced to fulfill the fractional output
    ///   rules, in the cheapest way possible.
    pub fn add_presigned_partial_fill_input(
        &mut self,
        sci: SignedContingentInput,
        sci_change_amount: Amount,
    ) -> Result<Vec<Amount>, SignedContingentInputError> {
        if !self.block_version.masked_amount_v2_is_supported() {
            return Err(
                SignedContingentInputError::FeatureNotSupportedAtBlockVersion(
                    *self.block_version,
                    "partial fills".into(),
                ),
            );
        }
        // Check if the sci already has membership proofs, the caller is supposed to do
        // that
        if sci.tx_in.ring.len() != sci.tx_in.proofs.len() {
            return Err(SignedContingentInputError::MissingProofs);
        }
        let rules = sci
            .tx_in
            .input_rules
            .as_ref()
            .ok_or(SignedContingentInputError::MissingRules)?;
        let partial_fill_change = rules
            .partial_fill_change
            .as_ref()
            .ok_or(SignedContingentInputError::MissingPartialFillChange)?;
        let (partial_fill_change_amount, partial_fill_change_blinding) =
            partial_fill_change.reveal_amount()?;
        if partial_fill_change_amount.value == 0 {
            return Err(SignedContingentInputError::ZeroPartialFillChange);
        }
        if rules.min_partial_fill_value > partial_fill_change_amount.value {
            return Err(SignedContingentInputError::MinPartialFillValueExceedsPartialChange);
        }
        if partial_fill_change_amount.token_id != sci_change_amount.token_id {
            return Err(SignedContingentInputError::TokenIdMismatch);
        }
        // Check if the user-provided amont of change would violate the
        // min_partial_fill_value rule imposed by the originator. (This is the
        // same check performed by input rules validation.)
        if partial_fill_change_amount.value - rules.min_partial_fill_value < sci_change_amount.value
        {
            return Err(SignedContingentInputError::ChangeLimitExceeded);
        }

        let fill_fraction = U64Ratio::new(
            partial_fill_change_amount.value - sci_change_amount.value,
            partial_fill_change_amount.value,
        )
        .ok_or(SignedContingentInputError::ZeroPartialFillChange)?;

        // Ensure that we can reveal all amounts
        let partial_fill_outputs_and_amounts: Vec<(&RevealedTxOut, Amount, Scalar)> = rules
            .partial_fill_outputs
            .iter()
            .map(
                |r_tx_out| -> Result<(&RevealedTxOut, Amount, Scalar), RevealedTxOutError> {
                    let (amount, blinding) = r_tx_out.reveal_amount()?;
                    Ok((r_tx_out, amount, blinding))
                },
            )
            .collect::<Result<_, _>>()?;

        // Add fractional outputs (corresponding to partial fill outputs) into the list
        // which is added to tx prefix
        let fractional_amounts = partial_fill_outputs_and_amounts
            .into_iter()
            .map(
                |(r_tx_out, amount, blinding)| -> Result<Amount, RevealedTxOutError> {
                    let fractional_amount = Amount::new(
                        fill_fraction
                            .checked_mul_round_up(amount.value)
                            .expect("should be unreachable, because fill fraction is <= 1"),
                        amount.token_id,
                    );
                    let fractional_tx_out = r_tx_out.change_committed_amount(fractional_amount)?;

                    // Note: The blinding factor has to be the same as the blinding factor of the
                    // partial fill output that this tx out came from. This
                    // invariant of .change_committed_amount is checked by a debug assertion.
                    let output_secret = OutputSecret {
                        amount: fractional_amount,
                        blinding,
                    };

                    self.outputs.push(TxBlueprintOutput::Sci {
                        output: fractional_tx_out,
                        unmasked_amount: output_secret.into(),
                    });

                    Ok(fractional_amount)
                },
            )
            .collect::<Result<Vec<_>, _>>()?;

        // Add the fractional change output
        {
            let fractional_change =
                partial_fill_change.change_committed_amount(sci_change_amount)?;

            // Note: The blinding factor has to be the same as the blinding factor of the
            // partial fill change that this txout came from. This invariant of
            // .change_committed_amount is checked by a debug assertion.
            let output_secret = OutputSecret {
                amount: sci_change_amount,
                blinding: partial_fill_change_blinding,
            };

            self.outputs.push(TxBlueprintOutput::Sci {
                output: fractional_change,
                unmasked_amount: output_secret.into(),
            });
        }

        self.add_presigned_input_helper(sci)?;
        Ok(fractional_amounts)
    }

    /// Add a pre-signed input to the transaction, fulfilling the MCIP 31 rules
    /// (but not checking any of the MCIP 42 rules).
    /// This is extracted to reduce code duplication between add_presigned_input
    /// and add_presigned_partial_fill_input.
    fn add_presigned_input_helper(
        &mut self,
        sci: SignedContingentInput,
    ) -> Result<(), SignedContingentInputError> {
        if *self.block_version != sci.block_version {
            return Err(SignedContingentInputError::BlockVersionMismatch(
                *self.block_version,
                sci.block_version,
            ));
        }
        // Check if the sci already has membership proofs, the caller is supposed to do
        // that
        if sci.tx_in.ring.len() != sci.tx_in.proofs.len() {
            return Err(SignedContingentInputError::MissingProofs);
        }

        let rules = sci
            .tx_in
            .input_rules
            .as_ref()
            .ok_or(SignedContingentInputError::MissingRules)?;

        // Enforce all non-partial fill rules so that our transaction will be valid
        if rules.required_outputs.len() != sci.required_output_amounts.len() {
            return Err(SignedContingentInputError::WrongNumberOfRequiredOutputAmounts);
        }
        // 1. Required outputs
        for (required_output, unmasked_amount) in rules
            .required_outputs
            .iter()
            .zip(sci.required_output_amounts.iter())
        {
            // Check if the required output is already there
            if !self
                .outputs
                .iter()
                .any(|output| matches!(output, TxBlueprintOutput::Sci { output: tx_out, .. } if tx_out == required_output))
            {
                // If not, add it
                self.outputs
                    .push(TxBlueprintOutput::Sci {
                        output: required_output.clone(),
                        unmasked_amount: unmasked_amount.clone(),
                    });
            }
        }
        // 2. Max tombstone block
        if rules.max_tombstone_block != 0 {
            self.impose_tombstone_block_limit(rules.max_tombstone_block);
        }

        // Don't do anything about partial fill rules, caller was supposed to do
        // that if they are present.
        // Now just add the sci to the list of inputs.
        self.add_presigned_input_raw(sci);
        Ok(())
    }

    /// Add a pre-signed Input to the transaction, without also fulfilling
    /// any of its rules. You will have to add any required outputs, adjust
    /// tombstone block, etc., for the transaction to be valid.
    ///
    /// Note: Before adding a signed_contingent_input, you probably want to:
    /// * validate it (call .validate())
    /// * check if key image appreared already (call .key_image())
    /// * provide merkle proofs of membership for each ring member (see
    ///   .tx_out_global_indices)
    ///
    /// # Arguments
    /// * `signed_contingent_input` - The pre-signed input we are adding
    pub fn add_presigned_input_raw(&mut self, sci: SignedContingentInput) {
        self.input_materials.push(InputMaterials::Presigned(sci));
    }

    /// Add a non-change output to the transaction.
    ///
    /// If a sender memo credential has been set, this will create an
    /// authenticated sender memo for the TxOut. Otherwise the memo will be
    /// unused.
    ///
    /// # Arguments
    /// * `amount` - The amount of this output
    /// * `recipient` - The recipient's public address
    /// * `rng` - RNG used to generate blinding for commitment
    pub fn add_output<RNG: CryptoRng + RngCore>(
        &mut self,
        amount: Amount,
        recipient: &PublicAddress,
        rng: &mut RNG,
    ) -> Result<TxOutContext, TxBuilderError> {
        self.add_output_with_tx_private_key(amount, recipient, None, rng)
    }

    /// Add a non-change output to the transaction, optionally with a specified
    /// tx_private_key.
    ///
    /// Specifying the tx_private_key gives you two things:
    ///
    /// * Together with the amount and recipient, fixes the generated TxOut
    ///   public key, target key, and blinding factor for amount. Because the
    ///   blockchain enforces that TxOut public keys are unique, this is a point
    ///   of mutual exclusion, and you can use this to create idempotent payment
    ///   interfaces.
    /// * If you know the tx private key, you can prove to an untrusting third
    ///   party what the amount and recipient of the tx out is. You can use this
    ///   resolve disputes. The TxOut shared secret and confirmation numbers
    ///   don't accomplish this because they don't reveal the recipient.
    ///
    /// If the tx_private_key is not pseudorandom, it will harm the privacy of
    /// transactions. For a merchant or exchange, a reasonable way to derive
    /// it is to hash the payment id, or the withdrawal id, together with a
    /// 32 byte secret. (You could use your private spend key or similar for
    /// example, but you may wish to rotate that from time to time, and you
    /// may not expect that idempotence would break across that key rotation.
    /// It's up to the application developer to decide the most suitable
    /// scheme.) You must ensure 32 bytes of pseudo-entropy to avoid
    /// undermining the transaction protocol.
    ///
    /// An alternative is to seed the RNG that is used with the transaction
    /// builder and then call add_output as usual. However, this approach
    /// means that upgrading your RNG is a way that idempotence can break,
    /// and in many cases, breaking idempotence means risk of double payments /
    /// loss of funds. Setting the tx_private_key directly is possibly
    /// simpler and with fewer hazards. Additionally, this approach allows
    /// you to easily determine and record the tx_private_key, which you may
    /// want for other reasons as described.
    ///
    /// # Arguments
    /// * `amount` - The amount of this output
    /// * `recipient` - The recipient's public address
    /// * `tx_private_key` - Optionally, a specific tx_private_key to use for
    ///   this output.
    /// * `rng` - RNG used to generate blinding for commitment
    pub fn add_output_with_tx_private_key<RNG: CryptoRng + RngCore>(
        &mut self,
        amount: Amount,
        recipient: &PublicAddress,
        tx_private_key: Option<RistrettoPrivate>,
        rng: &mut RNG,
    ) -> Result<TxOutContext, TxBuilderError> {
        self.add_output_with_fog_hint_address(amount, recipient, recipient, tx_private_key, rng)
    }

    /// Add a standard change output to the transaction.
    ///
    /// The change output is meant to send any value in the inputs not already
    /// sent via outputs or fee, back to the sender's address.
    /// The caller should ensure that the math adds up, and that
    /// change_value + total_outlays + fee = total_input_value
    ///
    /// (Here, outlay means a non-change output).
    ///
    /// A change output should be sent to the dedicated change subaddress of the
    /// sender.
    ///
    /// If provided, a Destination memo is attached to this output, which allows
    /// for recoverable transaction history.
    ///
    /// The use of dedicated change subaddress for change outputs allows to
    /// authenticate the contents of destination memos, which are otherwise
    /// unauthenticated.
    ///
    /// CHANGE OUTPUTS FOR GIFT CODES:
    /// -------------------------------
    /// Change outputs can track info about funding, redeeming or cancelling
    /// gift codes via memos which can are documented in transaction/std/memo
    ///
    /// A gift code is funded with add_gift_code_output. Any value remaining +
    /// the optional GiftCodeFundingMemo is written to the change output
    ///
    /// For gift code redemption & cancellation, the amount of the gift code is
    /// sent to the change address of the caller. In these cases the amount
    /// passed to this method should be: amount = gift_code_amount - fee.
    /// -------------------------------
    ///
    /// # Arguments
    /// * `amount` - The amount of this change output.
    /// * `change_destination` - An object including both a primary address and
    ///   a change subaddress to use to create this change output. The primary
    ///   address is used for the fog hint, the change subaddress owns the
    ///   change output. These can both be obtained from an account key, but
    ///   this API does not require the account key.
    /// * `rng` - RNG used to generate blinding for commitment
    pub fn add_change_output<RNG: CryptoRng + RngCore>(
        &mut self,
        amount: Amount,
        change_destination: &ReservedSubaddresses,
        rng: &mut RNG,
    ) -> Result<TxOutContext, TxBuilderError> {
        let (hint, pubkey_expiry) = create_fog_hint(
            &change_destination.primary_address,
            &*self.fog_resolver,
            rng,
        )?;

        if !self.block_version.mixed_transactions_are_supported()
            && self.fee.token_id != amount.token_id
        {
            return Err(TxBuilderError::MixedTransactionsNotAllowed(
                self.fee.token_id,
                amount.token_id,
            ));
        }

        let tx_private_key = RistrettoPrivate::from_random(rng);

        self.outputs.push(TxBlueprintOutput::Change {
            change_destination: change_destination.clone(),
            amount,
            e_fog_hint: hint,
            tx_private_key,
        });

        self.impose_tombstone_block_limit(pubkey_expiry);

        let shared_secret = create_shared_secret(
            change_destination.change_subaddress.view_public_key(),
            &tx_private_key,
        );
        let confirmation = TxOutConfirmationNumber::from(&shared_secret);

        let tx_out_public_key = create_tx_out_public_key(
            &tx_private_key,
            change_destination.change_subaddress.spend_public_key(),
        )
        .into();

        Ok(TxOutContext {
            tx_out_public_key,
            confirmation,
            shared_secret,
        })
    }

    /// Add an output to the reserved subaddress for gift codes
    ///
    /// The gift code subaddress is meant for reserving TxOuts for usage
    /// at a later time. This method creates outputs to that address in
    /// a way that Fog can track by creating a Fog hint for the primary
    /// account. This allows Fog users who send TxOuts to this address to
    /// track reserved TxOuts and if they desire, let other Fog users find
    /// these TxOuts and spend them at a later time. This enables
    /// functionality like sending "gift codes" to individuals who may not
    /// have a MobileCoin account and "red envelopes".
    ///
    /// The caller should ensure that the math adds up, and that
    /// change_value + gift_code_amount + fee = total_input_value
    ///
    /// # Arguments
    /// * `amount` - The amount of the "gift code"
    /// * `reserved_subaddreses` - A ReservedSubaddresses object which provides
    ///   all standard reserved addresses for the caller. This is used to set
    ///   the caller's primary address as the Fog hint address and set their
    ///   gift code subaddresses as the TxOut recipient.
    /// * `rng` - RNG used to generate blinding for commitment
    pub fn add_gift_code_output<RNG: CryptoRng + RngCore>(
        &mut self,
        amount: Amount,
        reserved_subaddresses: &ReservedSubaddresses,
        rng: &mut RNG,
    ) -> Result<TxOutContext, TxBuilderError> {
        self.add_output_with_fog_hint_address(
            amount,
            &reserved_subaddresses.gift_code_subaddress,
            &reserved_subaddresses.primary_address,
            None,
            rng,
        )
    }

    /// Add an output to the transaction, using `fog_hint_address` to construct
    /// the fog hint.
    ///
    /// This is a private implementation detail, and generally, fog users expect
    /// that the transactions that they recieve from fog belong to the account
    /// that they are using. The only known use-case where recipient and
    /// fog_hint_address are different is when sending change transactions
    /// to oneself, when oneself is a fog user. Sending the change to the
    /// main subaddress means that you don't have to hit fog once for the
    /// main subaddress and once for the change subaddress, so it cuts the
    /// number of requests in half.
    ///
    /// # Arguments
    /// * `amount` - The amount of this output
    /// * `recipient` - The recipient's public address
    /// * `fog_hint_address` - The public address used to create the fog hint
    /// * `tx_private_key` - Optional. If unspecified, generated randomly using
    ///   rng.
    /// * `memo_fn` - The memo function to use (see TxOut::new_with_memo)
    /// * `rng` - RNG used to generate tx private key (if not specified), and
    ///   encrypted fog hint
    fn add_output_with_fog_hint_address<RNG: CryptoRng + RngCore>(
        &mut self,
        amount: Amount,
        recipient: &PublicAddress,
        fog_hint_address: &PublicAddress,
        tx_private_key: Option<RistrettoPrivate>,
        rng: &mut RNG,
    ) -> Result<TxOutContext, TxBuilderError> {
        let (hint, pubkey_expiry) = create_fog_hint(fog_hint_address, &*self.fog_resolver, rng)?;

        if !self.block_version.mixed_transactions_are_supported()
            && self.fee.token_id != amount.token_id
        {
            return Err(TxBuilderError::MixedTransactionsNotAllowed(
                self.fee.token_id,
                amount.token_id,
            ));
        }

        let tx_private_key = tx_private_key.unwrap_or_else(|| RistrettoPrivate::from_random(rng));

        self.outputs.push(TxBlueprintOutput::Recipient {
            recipient: recipient.clone(),
            amount,
            e_fog_hint: hint,
            tx_private_key,
        });

        self.impose_tombstone_block_limit(pubkey_expiry);

        let shared_secret = create_shared_secret(recipient.view_public_key(), &tx_private_key);
        let confirmation = TxOutConfirmationNumber::from(&shared_secret);

        let tx_out_public_key =
            create_tx_out_public_key(&tx_private_key, recipient.spend_public_key()).into();

        Ok(TxOutContext {
            tx_out_public_key,
            confirmation,
            shared_secret,
        })
    }

    /// Sets the tombstone block, clamping to smallest pubkey expiry value.
    ///
    /// # Arguments
    /// * `tombstone_block` - Tombstone block number.
    pub fn set_tombstone_block(&mut self, tombstone_block: u64) -> u64 {
        self.tombstone_block = min(tombstone_block, self.fog_tombstone_block_limit);
        self.tombstone_block
    }

    /// Reduce the fog_tombstone_block_limit value by the amount specified,
    /// and propagate this constraint to self.tombstone_block
    fn impose_tombstone_block_limit(&mut self, pubkey_expiry: u64) {
        // Reduce fog tombstone block limit value if necessary
        self.fog_tombstone_block_limit = min(self.fog_tombstone_block_limit, pubkey_expiry);
        // Reduce tombstone_block value if necessary
        self.tombstone_block = min(self.fog_tombstone_block_limit, self.tombstone_block);
    }

    /// Sets the transaction fee.
    ///
    /// # Arguments
    /// * `fee_value` - Transaction fee value, in smallest representable units.
    pub fn set_fee(&mut self, fee_value: u64) -> Result<(), TxBuilderError> {
        self.fee.value = fee_value;
        Ok(())
    }

    /// Gets the transaction fee.
    pub fn get_fee(&self) -> u64 {
        self.fee.value
    }

    /// Gets the fee token id
    pub fn get_fee_token_id(&self) -> TokenId {
        self.fee.token_id
    }

    /// Sets the minimum fee map.
    /// This is used to allow the enclave to reject the transaction if the
    /// client has used a different fee map than consensus is using, which
    /// could result in an information disclosure attack. (This is a
    /// TOB-MCCT-5 mitigation)
    pub fn set_fee_map(&mut self, fee_map: FeeMap) {
        self.fee_map = Some(fee_map);
    }

    /// Return blueprint that together with a memo builder can be used to
    /// produce an unsigned tx.
    pub fn build_blueprint(mut self) -> Result<TxBlueprint, TxBuilderError> {
        // Note: Origin block has block version zero, so some clients like slam that
        // start with a bootstrapped ledger will target block version 0. However,
        // block version zero has no special rules and so targeting block version 0
        // should be the same as targeting block version 1, for the transaction
        // builder. This test is mainly here in case we decide that the
        // transaction builder should stop supporting sufficiently old block
        // versions in the future, then we can replace the zero here with
        // something else.
        if self.block_version < BlockVersion::default() {
            return Err(TxBuilderError::BlockVersionTooOld(*self.block_version, 0));
        }

        if self.block_version > BlockVersion::MAX {
            return Err(TxBuilderError::BlockVersionTooNew(
                *self.block_version,
                *BlockVersion::MAX,
            ));
        }

        if !self.block_version.masked_token_id_feature_is_supported()
            && self.fee.token_id != Mob::ID
        {
            return Err(TxBuilderError::FeatureNotSupportedAtBlockVersion(
                *self.block_version,
                "nonzero token id",
            ));
        }

        if self.input_materials.is_empty() {
            return Err(TxBuilderError::NoInputs);
        }

        // All inputs must have rings of the same size.
        if self
            .input_materials
            .windows(2)
            .any(|win| win[0].ring_size() != win[1].ring_size())
        {
            return Err(TxBuilderError::InvalidRingSize);
        }

        for input in self.input_materials.iter() {
            if !self.block_version.mixed_transactions_are_supported()
                && input.amount().token_id != self.fee.token_id
            {
                return Err(TxBuilderError::MixedTransactionsNotAllowed(
                    self.fee.token_id,
                    input.amount().token_id,
                ));
            }

            match input {
                InputMaterials::Presigned(input) => {
                    if !self.block_version.signed_input_rules_are_supported() {
                        return Err(TxBuilderError::SignedInputRulesNotAllowed);
                    }
                    // TODO: Also validate membership proofs?
                    if input.tx_in.ring.len() != input.tx_in.proofs.len() {
                        return Err(TxBuilderError::MissingMembershipProofs);
                    }
                }
                InputMaterials::Signable(input) => {
                    // TODO: Also validate membership proofs?
                    if input.ring.len() != input.membership_proofs.len() {
                        return Err(TxBuilderError::MissingMembershipProofs);
                    }
                }
            }
        }

        // Construct a list of sorted inputs.
        // Inputs are sorted by the first ring element's public key. Note that each ring
        // is also sorted.
        self.input_materials
            .sort_by(|a, b| a.sort_key().cmp(b.sort_key()));

        let inputs: Vec<TxIn> = self.input_materials.iter().map(TxIn::from).collect();

        let rings = self
            .input_materials
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<InputRing>, _>>()?;

        Ok(TxBlueprint {
            inputs,
            rings,
            outputs: self.outputs,
            fee: self.fee,
            tombstone_block: self.tombstone_block,
            block_version: self.block_version,
        })
    }

    /// Return low level data to sign and construct transactions with external
    /// signers
    ///
    /// # Arguments
    /// * `memo_builder` - An object which creates memos for the TxOuts in this
    ///   transaction
    pub fn build_unsigned(
        self,
        memo_builder: impl MemoBuilder,
    ) -> Result<UnsignedTx, TxBuilderError> {
        self.build_unsigned_with_sorter::<DefaultTxOutputsOrdering>(memo_builder)
    }

    /// Consume the builder and return the transaction.
    pub fn build<RNG: CryptoRng + RngCore, S: RingSigner + ?Sized>(
        self,
        ring_signer: &S,
        memo_builder: impl MemoBuilder,
        rng: &mut RNG,
    ) -> Result<Tx, TxBuilderError> {
        self.build_with_comparer_internal::<RNG, DefaultTxOutputsOrdering, S>(
            ring_signer,
            memo_builder,
            rng,
        )
    }

    /// Consume the builder and return the transaction with a comparer.
    /// Used only in testing library.
    #[cfg(feature = "test-only")]
    pub fn build_with_sorter<
        RNG: CryptoRng + RngCore,
        O: TxOutputsOrdering,
        S: RingSigner + ?Sized,
    >(
        self,
        ring_signer: &S,
        memo_builder: impl MemoBuilder,
        rng: &mut RNG,
    ) -> Result<Tx, TxBuilderError> {
        self.build_with_comparer_internal::<RNG, O, S>(ring_signer, memo_builder, rng)
    }

    /// Return low level data to sign and construct transactions with external
    /// signers.
    ///
    /// Allows specifying a custom output ordering, which is useful for internal
    /// testing.
    fn build_unsigned_with_sorter<O: TxOutputsOrdering>(
        self,
        memo_builder: impl MemoBuilder,
    ) -> Result<UnsignedTx, TxBuilderError> {
        self.build_blueprint()?.to_unsigned_tx::<O>(memo_builder)
    }

    /// Consume the builder and return the transaction with a comparer
    /// (internal usage only).
    fn build_with_comparer_internal<
        RNG: CryptoRng + RngCore,
        O: TxOutputsOrdering,
        S: RingSigner + ?Sized,
    >(
        self,
        ring_signer: &S,
        memo_builder: impl MemoBuilder,
        rng: &mut RNG,
    ) -> Result<Tx, TxBuilderError> {
        let fee_map = self.fee_map.clone();
        let unsigned_tx = self.build_unsigned_with_sorter::<O>(memo_builder)?;
        Ok(unsigned_tx.sign(ring_signer, fee_map.as_ref(), rng)?)
    }
}

/// Creates a TxOut that sends `value` to `recipient` using the provided
/// `fog_hint` and `tx_private_key`.
///
/// # Arguments
/// * `block_version` - Block version rules to conform to
/// * `value` - Value of the output, in picoMOB.
/// * `recipient` - Recipient's address.
/// * `fog_hint` - The encrypted fog hint to use
/// * `memo_fn` - The memo function to use -- see TxOut::new_with_memo docu
/// * `tx_private_key` - The tx private key to use. This should be pseudorandom.
///
/// # Returns
/// * TxOut
/// * tx_out_shared_secret
pub(crate) fn create_output_with_fog_hint(
    block_version: BlockVersion,
    amount: Amount,
    recipient: &PublicAddress,
    fog_hint: EncryptedFogHint,
    memo_fn: impl FnOnce(MemoContext) -> Result<MemoPayload, NewMemoError>,
    tx_private_key: &RistrettoPrivate,
) -> Result<(TxOut, RistrettoPublic), TxBuilderError> {
    let tx_out = TxOut::new_with_memo(
        block_version,
        amount,
        recipient,
        tx_private_key,
        fog_hint,
        memo_fn,
    )?;

    let shared_secret = create_shared_secret(recipient.view_public_key(), tx_private_key);
    Ok((tx_out, shared_secret))
}

/// Create a fog hint, using the fog_resolver collection in self.
///
/// # Arguments
/// * `recipient` - Recipient's address.
/// * `fog_resolver` - Set of validated fog pubkey data
/// * `rng` - Entropy for the encryption.
///
/// # Returns
/// * `encrypted_fog_hint` - The fog hint to use for a TxOut.
/// * `pubkey_expiry` - The block at which this fog pubkey expires, or u64::MAX
///   Imposes a limit on tombstone block for the transaction
pub(crate) fn create_fog_hint<RNG: RngCore + CryptoRng, FPR: FogPubkeyResolver>(
    recipient: &PublicAddress,
    fog_resolver: &FPR,
    rng: &mut RNG,
) -> Result<(EncryptedFogHint, u64), TxBuilderError> {
    if recipient.fog_report_url().is_none() {
        return Ok((EncryptedFogHint::fake_onetime_hint(rng), u64::MAX));
    }

    // Find fog pubkey from set of pre-fetched fog pubkeys
    let validated_fog_pubkey = fog_resolver.get_fog_pubkey(recipient)?;

    Ok((
        FogHint::from(recipient).encrypt(&validated_fog_pubkey.pubkey, rng),
        validated_fog_pubkey.pubkey_expiry,
    ))
}

#[cfg(test)]
pub mod transaction_builder_tests {
    use super::*;
    use crate::{
        test_utils::{create_output, get_input_credentials, get_transaction},
        BurnRedemptionMemoBuilder, DefragmentationMemoBuilder, EmptyMemoBuilder,
        GiftCodeCancellationMemoBuilder, GiftCodeFundingMemoBuilder, GiftCodeSenderMemoBuilder,
        RTHMemoBuilder,
    };
    use alloc::{string::ToString, vec};
    use assert_matches::assert_matches;
    use maplit::btreemap;
    use mc_account_keys::{
        burn_address, burn_address_view_private, AccountKey, ShortAddressHash,
        CHANGE_SUBADDRESS_INDEX, DEFAULT_SUBADDRESS_INDEX, GIFT_CODE_SUBADDRESS_INDEX,
    };
    use mc_crypto_ring_signature_signer::{InputSecret, NoKeysRingSigner};
    use mc_fog_report_validation_test_utils::{FullyValidatedFogPubkey, MockFogResolver};
    use mc_transaction_core::{
        constants::{MAX_INPUTS, MAX_OUTPUTS, MILLIMOB_TO_PICOMOB},
        get_tx_out_shared_secret,
        onetime_keys::*,
        ring_signature::KeyImage,
        subaddress_matches_tx_out,
        tx::TxOutMembershipProof,
        validation::{validate_signature, validate_tx_out},
        NewTxError,
    };
    use mc_transaction_extra::{MemoType, SenderMemoCredential, TxOutGiftCode};
    use rand::{rngs::StdRng, SeedableRng};

    // Helper which produces a list of block_version, TokenId pairs to iterate over
    // in tests
    fn get_block_version_token_id_pairs() -> Vec<(BlockVersion, TokenId)> {
        vec![
            (BlockVersion::try_from(0).unwrap(), TokenId::from(0)),
            (BlockVersion::try_from(1).unwrap(), TokenId::from(0)),
            (BlockVersion::try_from(2).unwrap(), TokenId::from(0)),
            (BlockVersion::try_from(2).unwrap(), TokenId::from(1)),
            (BlockVersion::try_from(2).unwrap(), TokenId::from(2)),
        ]
    }

    fn single_input_transaction_builder<FPR: FogPubkeyResolver + Clone>(
        block_version: BlockVersion,
        token_id: TokenId,
        input_amount: u64,
        fog_resolver: &FPR,
        rng: &mut StdRng,
    ) -> TransactionBuilder<FPR> {
        let mut transaction_builder = TransactionBuilder::new(
            block_version,
            Amount::new(Mob::MINIMUM_FEE, token_id),
            fog_resolver.clone(),
        )
        .unwrap();
        transaction_builder.set_tombstone_block(2000);
        transaction_builder.add_input(get_input_credentials(
            block_version,
            Amount::new(input_amount, token_id),
            &AccountKey::random(rng),
            fog_resolver,
            rng,
        ));
        transaction_builder
    }

    #[track_caller]
    fn find_output<'a>(tx: &'a Tx, recipient: &AccountKey, subaddress_index: u64) -> &'a TxOut {
        tx.prefix
            .outputs
            .iter()
            .find(|tx_out| subaddress_matches_tx_out(recipient, subaddress_index, tx_out).unwrap())
            .expect("Didn't find output")
    }

    #[track_caller]
    fn validate_tx_outs(
        block_version: BlockVersion,
        sender: &AccountKey,
        tx_outs: &[(&TxOut, &AccountKey, u64)],
    ) {
        let all_subaddress_indices = tx_outs
            .iter()
            .map(|(_, _, subaddress_index)| *subaddress_index)
            .collect::<Vec<_>>();

        for (tx_out, recipient, subaddress_index) in tx_outs {
            validate_tx_out(block_version, tx_out).unwrap();
            assert!(subaddress_matches_tx_out(recipient, *subaddress_index, tx_out).unwrap());

            all_subaddress_indices.iter().for_each(|index| {
                if *index != *subaddress_index {
                    assert!(!subaddress_matches_tx_out(recipient, *index, tx_out).unwrap());
                }

                if &sender != recipient {
                    assert!(!subaddress_matches_tx_out(sender, *index, tx_out).unwrap());
                }
            });
        }
    }

    #[track_caller]
    fn validate_amount_and_get_memo(
        block_version: BlockVersion,
        tx_out: &TxOut,
        recipient: &AccountKey,
        expected_amount: Amount,
    ) -> Option<MemoType> {
        let ss = get_tx_out_shared_secret(
            recipient.view_private_key(),
            &RistrettoPublic::try_from(&tx_out.public_key).unwrap(),
        );
        let (amount, _) = tx_out.get_masked_amount().unwrap().get_value(&ss).unwrap();
        assert_eq!(amount, expected_amount);

        if block_version.e_memo_feature_is_supported() {
            let memo = tx_out.e_memo.unwrap().decrypt(&ss);
            Some(MemoType::try_from(&memo).expect("Couldn't decrypt memo"))
        } else {
            None
        }
    }

    #[test]
    // Spend a single input and send its full value to a single recipient.
    fn test_simple_transaction() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for (block_version, token_id) in get_block_version_token_id_pairs() {
            let fpr = MockFogResolver::default();
            let sender = AccountKey::random(&mut rng);
            let recipient = AccountKey::random(&mut rng);
            let value = 1475 * MILLIMOB_TO_PICOMOB;
            let amount = Amount { value, token_id };

            // Mint an initial collection of outputs, including one belonging to Alice.
            let input_credentials =
                get_input_credentials(block_version, amount, &sender, &fpr, &mut rng);

            let membership_proofs = input_credentials.membership_proofs.clone();
            let key_image = KeyImage::from(input_credentials.assert_has_onetime_private_key());

            let mut transaction_builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, token_id),
                fpr,
            )
            .unwrap();

            transaction_builder.add_input(input_credentials);
            let TxOutContext { confirmation, .. } = transaction_builder
                .add_output(
                    Amount::new(value - Mob::MINIMUM_FEE, token_id),
                    &recipient.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            let tx = transaction_builder
                .build(&NoKeysRingSigner {}, EmptyMemoBuilder, &mut rng)
                .unwrap();

            // The transaction should have a single input.
            assert_eq!(tx.prefix.inputs.len(), 1);

            assert_eq!(tx.prefix.inputs[0].proofs.len(), membership_proofs.len());

            let expected_key_images = vec![key_image];
            assert_eq!(tx.key_images(), expected_key_images);

            // The transaction should have one output.
            assert_eq!(tx.prefix.outputs.len(), 1);

            let output: &TxOut = tx.prefix.outputs.first().unwrap();

            validate_tx_out(block_version, output).unwrap();

            // The output should belong to the correct recipient.
            assert!(
                subaddress_matches_tx_out(&recipient, DEFAULT_SUBADDRESS_INDEX, output).unwrap()
            );

            // The output should have the correct value and confirmation number
            {
                let public_key = RistrettoPublic::try_from(&output.public_key).unwrap();
                assert!(confirmation.validate(&public_key, recipient.view_private_key()));
            }

            // The transaction should have a valid signature.
            assert!(validate_signature(block_version, &tx, &mut rng).is_ok());
        }
    }

    #[test]
    // Spend a single input and send its full value to a single fog recipient.
    fn test_simple_fog_transaction() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for (block_version, token_id) in get_block_version_token_id_pairs() {
            let sender = AccountKey::random(&mut rng);
            let recipient = AccountKey::random_with_fog(&mut rng);
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);

            let fog_resolver = MockFogResolver(btreemap! {
                                recipient
                        .default_subaddress()
                        .fog_report_url()
                        .unwrap()
                        .to_string()
                =>
                    FullyValidatedFogPubkey {
                        pubkey: RistrettoPublic::from(&ingest_private_key),
                        pubkey_expiry: 1000,
                    },
            });

            let value = 1475 * MILLIMOB_TO_PICOMOB;
            let amount = Amount { value, token_id };

            let input_credentials =
                get_input_credentials(block_version, amount, &sender, &fog_resolver, &mut rng);

            let membership_proofs = input_credentials.membership_proofs.clone();
            let key_image = KeyImage::from(input_credentials.assert_has_onetime_private_key());

            let mut transaction_builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, token_id),
                fog_resolver,
            )
            .unwrap();

            transaction_builder.add_input(input_credentials);
            let TxOutContext { confirmation, .. } = transaction_builder
                .add_output(
                    Amount::new(value - Mob::MINIMUM_FEE, token_id),
                    &recipient.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            let tx = transaction_builder
                .build(&NoKeysRingSigner {}, EmptyMemoBuilder, &mut rng)
                .unwrap();

            // The transaction should have a single input.
            assert_eq!(tx.prefix.inputs.len(), 1);

            assert_eq!(tx.prefix.inputs[0].proofs.len(), membership_proofs.len());

            let expected_key_images = vec![key_image];
            assert_eq!(tx.key_images(), expected_key_images);

            // The transaction should have one output.
            assert_eq!(tx.prefix.outputs.len(), 1);

            let output: &TxOut = tx.prefix.outputs.first().unwrap();

            validate_tx_out(block_version, output).unwrap();

            // The output should belong to the correct recipient.
            assert!(
                subaddress_matches_tx_out(&recipient, DEFAULT_SUBADDRESS_INDEX, output).unwrap()
            );

            // The output should have the correct value and confirmation number
            {
                let public_key = RistrettoPublic::try_from(&output.public_key).unwrap();
                assert!(confirmation.validate(&public_key, recipient.view_private_key()));
            }

            // The output's fog hint should contain the correct public key.
            {
                let mut output_fog_hint = FogHint::new(RistrettoPublic::from_random(&mut rng));
                assert!(bool::from(FogHint::ct_decrypt(
                    &ingest_private_key,
                    &output.e_fog_hint,
                    &mut output_fog_hint,
                )));
                assert_eq!(
                    output_fog_hint.get_view_pubkey(),
                    &CompressedRistrettoPublic::from(
                        recipient.default_subaddress().view_public_key()
                    )
                );
            }

            // The transaction should have a valid signature.
            assert!(validate_signature(block_version, &tx, &mut rng).is_ok());
        }
    }

    #[test]
    // Use a custom PublicAddress to create the fog hint.
    fn test_custom_fog_hint_address() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for (block_version, token_id) in get_block_version_token_id_pairs() {
            let recipient = AccountKey::random(&mut rng);
            let fog_hint_address = AccountKey::random_with_fog(&mut rng).default_subaddress();
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);
            let value = 1475 * MILLIMOB_TO_PICOMOB;

            let fog_resolver = MockFogResolver(btreemap! {
                                fog_hint_address
                        .fog_report_url()
                        .unwrap()
                        .to_string()
                =>
                    FullyValidatedFogPubkey {
                        pubkey: RistrettoPublic::from(&ingest_private_key),
                        pubkey_expiry: 1000,
                    },
            });

            let mut transaction_builder = single_input_transaction_builder(
                block_version,
                token_id,
                value,
                &fog_resolver,
                &mut rng,
            );

            let _tx_out_context = transaction_builder
                .add_output_with_fog_hint_address(
                    Amount::new(value - Mob::MINIMUM_FEE, token_id),
                    &recipient.default_subaddress(),
                    &fog_hint_address,
                    None,
                    &mut rng,
                )
                .unwrap();

            let tx = transaction_builder
                .build(&NoKeysRingSigner {}, EmptyMemoBuilder, &mut rng)
                .unwrap();

            // The transaction should have one output.
            assert_eq!(tx.prefix.outputs.len(), 1);

            let output: &TxOut = tx.prefix.outputs.first().unwrap();

            // The output should belong to the correct recipient.
            assert!(
                subaddress_matches_tx_out(&recipient, DEFAULT_SUBADDRESS_INDEX, output).unwrap()
            );

            // The output's fog hint should contain the correct public key.
            {
                let mut output_fog_hint = FogHint::new(RistrettoPublic::from_random(&mut rng));
                assert!(bool::from(FogHint::ct_decrypt(
                    &ingest_private_key,
                    &output.e_fog_hint,
                    &mut output_fog_hint,
                )));
                assert_eq!(
                    output_fog_hint.get_view_pubkey(),
                    &CompressedRistrettoPublic::from(fog_hint_address.view_public_key())
                );
            }
        }
    }

    #[test]
    // Test that fog pubkey expiry limit is enforced on the tombstone block
    fn test_fog_pubkey_expiry_limit_enforced() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for (block_version, token_id) in get_block_version_token_id_pairs() {
            let recipient = AccountKey::random_with_fog(&mut rng);
            let recipient_address = recipient.default_subaddress();
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);
            let value = 1475 * MILLIMOB_TO_PICOMOB;

            let fog_resolver = MockFogResolver(btreemap! {
                                recipient_address
                        .fog_report_url()
                        .unwrap()
                        .to_string()
                =>
                    FullyValidatedFogPubkey {
                        pubkey: RistrettoPublic::from(&ingest_private_key),
                        pubkey_expiry: 1000,
                    },
            });

            {
                let mut transaction_builder = single_input_transaction_builder(
                    block_version,
                    token_id,
                    value,
                    &fog_resolver,
                    &mut rng,
                );

                transaction_builder
                    .add_output(
                        Amount::new(value - Mob::MINIMUM_FEE, token_id),
                        &recipient_address,
                        &mut rng,
                    )
                    .unwrap();

                let tx = transaction_builder
                    .build(&NoKeysRingSigner {}, EmptyMemoBuilder, &mut rng)
                    .unwrap();

                // The transaction should have one output.
                assert_eq!(tx.prefix.outputs.len(), 1);

                validate_tx_out(block_version, tx.prefix.outputs.first().unwrap()).unwrap();

                // The tombstone block should be the min of what the user requested, and what
                // fog limits it to
                assert_eq!(tx.prefix.tombstone_block, 1000);
            }

            {
                let mut transaction_builder = single_input_transaction_builder(
                    block_version,
                    token_id,
                    value,
                    &fog_resolver,
                    &mut rng,
                );

                transaction_builder.set_tombstone_block(500);

                transaction_builder
                    .add_output(
                        Amount::new(value - Mob::MINIMUM_FEE, token_id),
                        &recipient_address,
                        &mut rng,
                    )
                    .unwrap();

                let tx = transaction_builder
                    .build(&NoKeysRingSigner {}, EmptyMemoBuilder, &mut rng)
                    .unwrap();

                // The transaction should have one output.
                assert_eq!(tx.prefix.outputs.len(), 1);

                validate_tx_out(block_version, tx.prefix.outputs.first().unwrap()).unwrap();

                // The tombstone block should be the min of what the user requested, and what
                // fog limits it to
                assert_eq!(tx.prefix.tombstone_block, 500);
            }
        }
    }

    #[test]
    // Test that sending a fog transaction with change, and recoverable transaction
    // history, produces appropriate memos
    fn test_fog_transaction_with_change() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for (block_version, token_id) in get_block_version_token_id_pairs() {
            let sender = AccountKey::random_with_fog(&mut rng);
            let sender_change_dest = ReservedSubaddresses::from(&sender);
            let recipient = AccountKey::random_with_fog(&mut rng);
            let recipient_address = recipient.default_subaddress();
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);
            let value = 1475 * MILLIMOB_TO_PICOMOB;
            let change_value = 128 * MILLIMOB_TO_PICOMOB;

            let fog_resolver = MockFogResolver(btreemap! {
                                recipient_address
                        .fog_report_url()
                        .unwrap()
                        .to_string()
                =>
                    FullyValidatedFogPubkey {
                        pubkey: RistrettoPublic::from(&ingest_private_key),
                        pubkey_expiry: 1000,
                    },
            });

            {
                let mut transaction_builder = single_input_transaction_builder(
                    block_version,
                    token_id,
                    value,
                    &fog_resolver,
                    &mut rng,
                );

                transaction_builder
                    .add_output(
                        Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                        &recipient_address,
                        &mut rng,
                    )
                    .unwrap();

                transaction_builder
                    .add_change_output(
                        Amount::new(change_value, token_id),
                        &sender_change_dest,
                        &mut rng,
                    )
                    .unwrap();

                let tx = transaction_builder
                    .build(&NoKeysRingSigner {}, EmptyMemoBuilder, &mut rng)
                    .unwrap();

                // The transaction should have two output.
                assert_eq!(tx.prefix.outputs.len(), 2);

                // The tombstone block should be the min of what the user requested, and what
                // fog limits it to
                assert_eq!(tx.prefix.tombstone_block, 1000);

                let output = find_output(&tx, &recipient, DEFAULT_SUBADDRESS_INDEX);
                let change = find_output(&tx, &sender, CHANGE_SUBADDRESS_INDEX);
                validate_tx_outs(
                    block_version,
                    &sender,
                    &[
                        (output, &recipient, DEFAULT_SUBADDRESS_INDEX),
                        (change, &sender, CHANGE_SUBADDRESS_INDEX),
                    ],
                );

                // The 1st output should belong to the correct recipient and have correct amount
                // and have an empty memo
                {
                    let ss = get_tx_out_shared_secret(
                        recipient.view_private_key(),
                        &RistrettoPublic::try_from(&output.public_key).unwrap(),
                    );
                    let (amount, _) = output.get_masked_amount().unwrap().get_value(&ss).unwrap();
                    assert_eq!(amount.value, value - change_value - Mob::MINIMUM_FEE);
                    assert_eq!(amount.token_id, token_id);

                    if block_version.e_memo_feature_is_supported() {
                        let memo = output.e_memo.unwrap().decrypt(&ss);
                        assert_eq!(memo, MemoPayload::default());
                    }
                }

                // The 1st output's fog hint should contain the correct public key.
                {
                    let mut output_fog_hint = FogHint::new(RistrettoPublic::from_random(&mut rng));
                    assert!(bool::from(FogHint::ct_decrypt(
                        &ingest_private_key,
                        &output.e_fog_hint,
                        &mut output_fog_hint,
                    )));
                    assert_eq!(
                        output_fog_hint.get_view_pubkey(),
                        &CompressedRistrettoPublic::from(recipient_address.view_public_key())
                    );
                }

                // The 2nd output should belong to the correct recipient and have correct amount
                // and have empty memo
                {
                    let ss = get_tx_out_shared_secret(
                        sender.view_private_key(),
                        &RistrettoPublic::try_from(&change.public_key).unwrap(),
                    );
                    let (amount, _) = change.get_masked_amount().unwrap().get_value(&ss).unwrap();
                    assert_eq!(amount.value, change_value);
                    assert_eq!(amount.token_id, token_id);

                    if block_version.e_memo_feature_is_supported() {
                        let memo = change.e_memo.unwrap().decrypt(&ss);
                        assert_eq!(memo, MemoPayload::default());
                    }
                }

                // The 2nd output's fog hint should contain the correct public key.
                {
                    let mut output_fog_hint = FogHint::new(RistrettoPublic::from_random(&mut rng));
                    assert!(bool::from(FogHint::ct_decrypt(
                        &ingest_private_key,
                        &change.e_fog_hint,
                        &mut output_fog_hint,
                    )));
                    assert_eq!(
                        output_fog_hint.get_view_pubkey(),
                        &CompressedRistrettoPublic::from(
                            sender.default_subaddress().view_public_key()
                        )
                    );
                }
            }
        }
    }

    #[test]
    // Test that sending a fog transaction with change, using add_change_output
    // produces change owned by the sender as expected, with appropriate memos
    fn test_fog_transaction_with_change_and_rth_memos() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for (block_version, token_id) in get_block_version_token_id_pairs() {
            let sender = AccountKey::random_with_fog(&mut rng);
            let sender_addr = sender.default_subaddress();
            let sender_change_dest = ReservedSubaddresses::from(&sender);
            let recipient = AccountKey::random_with_fog(&mut rng);
            let recipient_address = recipient.default_subaddress();
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);
            let value = 1475 * MILLIMOB_TO_PICOMOB;
            let change_value = 128 * MILLIMOB_TO_PICOMOB;

            let fog_resolver = MockFogResolver(btreemap! {
                                recipient_address
                        .fog_report_url()
                        .unwrap()
                        .to_string()
                =>
                    FullyValidatedFogPubkey {
                        pubkey: RistrettoPublic::from(&ingest_private_key),
                        pubkey_expiry: 1000,
                    },
            });

            // Enable both sender and destination memos
            {
                let mut memo_builder = RTHMemoBuilder::default();
                memo_builder.set_sender_credential(SenderMemoCredential::from(&sender));
                memo_builder.enable_destination_memo();

                let mut transaction_builder = single_input_transaction_builder(
                    block_version,
                    token_id,
                    value,
                    &fog_resolver,
                    &mut rng,
                );

                transaction_builder
                    .add_output(
                        Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                        &recipient_address,
                        &mut rng,
                    )
                    .unwrap();

                transaction_builder
                    .add_change_output(
                        Amount::new(change_value, token_id),
                        &sender_change_dest,
                        &mut rng,
                    )
                    .unwrap();

                let tx = transaction_builder
                    .build(&NoKeysRingSigner {}, memo_builder, &mut rng)
                    .unwrap();

                // The transaction should have two output.
                assert_eq!(tx.prefix.outputs.len(), 2);

                // The tombstone block should be the min of what the user requested, and what
                // fog limits it to
                assert_eq!(tx.prefix.tombstone_block, 1000);

                let output = find_output(&tx, &recipient, DEFAULT_SUBADDRESS_INDEX);
                let change = find_output(&tx, &sender, CHANGE_SUBADDRESS_INDEX);
                validate_tx_outs(
                    block_version,
                    &sender,
                    &[
                        (output, &recipient, DEFAULT_SUBADDRESS_INDEX),
                        (change, &sender, CHANGE_SUBADDRESS_INDEX),
                    ],
                );

                // The 1st output should belong to the correct recipient and have correct amount
                // and have correct memo
                {
                    let memo = validate_amount_and_get_memo(
                        block_version,
                        output,
                        &recipient,
                        Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                    );

                    if block_version.e_memo_feature_is_supported() {
                        let MemoType::AuthenticatedSender(memo) = memo.unwrap() else {
                            panic!("unexpected memo type")
                        };

                        assert_eq!(
                            memo.sender_address_hash(),
                            ShortAddressHash::from(&sender_addr),
                            "lookup based on address hash failed"
                        );
                        assert!(
                            bool::from(memo.validate(
                                &sender_addr,
                                &recipient.subaddress_view_private(DEFAULT_SUBADDRESS_INDEX),
                                &output.public_key,
                            )),
                            "hmac validation failed"
                        );
                    }
                }

                // The 2nd output should belong to the correct recipient and have correct amount
                // and have correct memo
                {
                    let memo = validate_amount_and_get_memo(
                        block_version,
                        change,
                        &sender,
                        Amount::new(change_value, token_id),
                    );

                    if block_version.e_memo_feature_is_supported() {
                        let MemoType::Destination(memo) = memo.unwrap() else {
                            panic!("unexpected memo type")
                        };

                        assert_eq!(
                            memo.get_address_hash(),
                            &ShortAddressHash::from(&recipient_address),
                            "lookup based on address hash failed"
                        );
                        assert_eq!(memo.get_num_recipients(), 1);
                        assert_eq!(memo.get_fee(), Mob::MINIMUM_FEE);
                        assert_eq!(
                            memo.get_total_outlay(),
                            value - change_value,
                            "outlay should be amount sent to recipient + fee"
                        );
                    }
                }
            }

            // Enable both sender and destination memos, and try increasing the fee
            {
                let mut memo_builder = RTHMemoBuilder::default();
                memo_builder.set_sender_credential(SenderMemoCredential::from(&sender));
                memo_builder.enable_destination_memo();

                let mut transaction_builder = single_input_transaction_builder(
                    block_version,
                    token_id,
                    value,
                    &fog_resolver,
                    &mut rng,
                );
                transaction_builder.set_fee(Mob::MINIMUM_FEE * 4).unwrap();
                transaction_builder
                    .add_output(
                        Amount::new(value - change_value - 4 * Mob::MINIMUM_FEE, token_id),
                        &recipient_address,
                        &mut rng,
                    )
                    .unwrap();

                transaction_builder
                    .add_change_output(
                        Amount::new(change_value, token_id),
                        &sender_change_dest,
                        &mut rng,
                    )
                    .unwrap();

                let tx = transaction_builder
                    .build(&NoKeysRingSigner {}, memo_builder, &mut rng)
                    .unwrap();

                // The transaction should have two output.
                assert_eq!(tx.prefix.outputs.len(), 2);

                // The tombstone block should be the min of what the user requested, and what
                // fog limits it to
                assert_eq!(tx.prefix.tombstone_block, 1000);

                let output = find_output(&tx, &recipient, DEFAULT_SUBADDRESS_INDEX);
                let change = find_output(&tx, &sender, CHANGE_SUBADDRESS_INDEX);
                validate_tx_outs(
                    block_version,
                    &sender,
                    &[
                        (output, &recipient, DEFAULT_SUBADDRESS_INDEX),
                        (change, &sender, CHANGE_SUBADDRESS_INDEX),
                    ],
                );

                // The 1st output should belong to the correct recipient and have correct amount
                // and have correct memo
                {
                    let memo = validate_amount_and_get_memo(
                        block_version,
                        output,
                        &recipient,
                        Amount::new(value - change_value - Mob::MINIMUM_FEE * 4, token_id),
                    );

                    if block_version.e_memo_feature_is_supported() {
                        let MemoType::AuthenticatedSender(memo) = memo.unwrap() else {
                            panic!("unexpected memo type")
                        };

                        assert_eq!(
                            memo.sender_address_hash(),
                            ShortAddressHash::from(&sender_addr),
                            "lookup based on address hash failed"
                        );
                        assert!(
                            bool::from(memo.validate(
                                &sender_addr,
                                &recipient.subaddress_view_private(DEFAULT_SUBADDRESS_INDEX),
                                &output.public_key,
                            )),
                            "hmac validation failed"
                        );
                    }
                }

                // The 2nd output should belong to the correct recipient and have correct amount
                // and have correct memo
                {
                    let memo = validate_amount_and_get_memo(
                        block_version,
                        change,
                        &sender,
                        Amount::new(change_value, token_id),
                    );

                    if block_version.e_memo_feature_is_supported() {
                        let MemoType::Destination(memo) = memo.unwrap() else {
                            panic!("unexpected memo type")
                        };

                        assert_eq!(
                            memo.get_address_hash(),
                            &ShortAddressHash::from(&recipient_address),
                            "lookup based on address hash failed"
                        );
                        assert_eq!(memo.get_num_recipients(), 1);
                        assert_eq!(memo.get_fee(), Mob::MINIMUM_FEE * 4);
                        assert_eq!(
                            memo.get_total_outlay(),
                            value - change_value,
                            "outlay should be amount sent to recipient + fee"
                        );
                    }
                }
            }

            // Enable both sender and destination memos, and set a payment request id
            {
                let mut memo_builder = RTHMemoBuilder::default();
                memo_builder.set_sender_credential(SenderMemoCredential::from(&sender));
                memo_builder.enable_destination_memo();
                memo_builder.set_payment_request_id(42);

                let mut transaction_builder = single_input_transaction_builder(
                    block_version,
                    token_id,
                    value,
                    &fog_resolver,
                    &mut rng,
                );

                transaction_builder
                    .add_output(
                        Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                        &recipient_address,
                        &mut rng,
                    )
                    .unwrap();

                transaction_builder
                    .add_change_output(
                        Amount::new(change_value, token_id),
                        &sender_change_dest,
                        &mut rng,
                    )
                    .unwrap();

                let tx = transaction_builder
                    .build(&NoKeysRingSigner {}, memo_builder, &mut rng)
                    .unwrap();

                // The transaction should have two output.
                assert_eq!(tx.prefix.outputs.len(), 2);

                // The tombstone block should be the min of what the user requested, and what
                // fog limits it to
                assert_eq!(tx.prefix.tombstone_block, 1000);

                let output = find_output(&tx, &recipient, DEFAULT_SUBADDRESS_INDEX);
                let change = find_output(&tx, &sender, CHANGE_SUBADDRESS_INDEX);
                validate_tx_outs(
                    block_version,
                    &sender,
                    &[
                        (output, &recipient, DEFAULT_SUBADDRESS_INDEX),
                        (change, &sender, CHANGE_SUBADDRESS_INDEX),
                    ],
                );

                // The 1st output should belong to the correct recipient and have correct amount
                // and have correct memo
                {
                    let memo = validate_amount_and_get_memo(
                        block_version,
                        output,
                        &recipient,
                        Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                    );

                    if block_version.e_memo_feature_is_supported() {
                        let MemoType::AuthenticatedSenderWithPaymentRequestId(memo) = memo.unwrap()
                        else {
                            panic!("unexpected memo type")
                        };

                        assert_eq!(
                            memo.sender_address_hash(),
                            ShortAddressHash::from(&sender_addr),
                            "lookup based on address hash failed"
                        );
                        assert!(
                            bool::from(memo.validate(
                                &sender_addr,
                                &recipient.subaddress_view_private(DEFAULT_SUBADDRESS_INDEX),
                                &output.public_key,
                            )),
                            "hmac validation failed"
                        );
                        assert_eq!(memo.payment_request_id(), 42);
                    }
                }

                // The 2nd output should belong to the correct recipient and have correct amount
                // and have correct memo
                {
                    let memo = validate_amount_and_get_memo(
                        block_version,
                        change,
                        &sender,
                        Amount::new(change_value, token_id),
                    );

                    if block_version.e_memo_feature_is_supported() {
                        let MemoType::DestinationWithPaymentRequestId(memo) = memo.unwrap() else {
                            panic!("unexpected memo type")
                        };

                        assert_eq!(
                            memo.get_address_hash(),
                            &ShortAddressHash::from(&recipient_address),
                            "lookup based on address hash failed"
                        );
                        assert_eq!(memo.get_num_recipients(), 1);
                        assert_eq!(memo.get_fee(), Mob::MINIMUM_FEE);
                        assert_eq!(
                            memo.get_total_outlay(),
                            value - change_value,
                            "outlay should be amount sent to recipient + fee"
                        );
                        assert_eq!(memo.get_payment_request_id(), 42);
                    }
                }
            }

            // Enable sender memos, and set a payment request id, no destination_memo
            {
                let mut memo_builder = RTHMemoBuilder::default();
                memo_builder.set_sender_credential(SenderMemoCredential::from(&sender));
                memo_builder.set_payment_request_id(47);

                let mut transaction_builder = single_input_transaction_builder(
                    block_version,
                    token_id,
                    value,
                    &fog_resolver,
                    &mut rng,
                );

                transaction_builder
                    .add_output(
                        Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                        &recipient_address,
                        &mut rng,
                    )
                    .unwrap();

                transaction_builder
                    .add_change_output(
                        Amount::new(change_value, token_id),
                        &sender_change_dest,
                        &mut rng,
                    )
                    .unwrap();

                let tx = transaction_builder
                    .build(&NoKeysRingSigner {}, memo_builder, &mut rng)
                    .unwrap();

                // The transaction should have two output.
                assert_eq!(tx.prefix.outputs.len(), 2);

                // The tombstone block should be the min of what the user requested, and what
                // fog limits it to
                assert_eq!(tx.prefix.tombstone_block, 1000);

                let output = find_output(&tx, &recipient, DEFAULT_SUBADDRESS_INDEX);
                let change = find_output(&tx, &sender, CHANGE_SUBADDRESS_INDEX);
                validate_tx_outs(
                    block_version,
                    &sender,
                    &[
                        (output, &recipient, DEFAULT_SUBADDRESS_INDEX),
                        (change, &sender, CHANGE_SUBADDRESS_INDEX),
                    ],
                );

                // The 1st output should belong to the correct recipient and have correct amount
                // and have correct memo
                {
                    let memo = validate_amount_and_get_memo(
                        block_version,
                        output,
                        &recipient,
                        Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                    );

                    if block_version.e_memo_feature_is_supported() {
                        let MemoType::AuthenticatedSenderWithPaymentRequestId(memo) = memo.unwrap()
                        else {
                            panic!("unexpected memo type")
                        };

                        assert_eq!(
                            memo.sender_address_hash(),
                            ShortAddressHash::from(&sender_addr),
                            "lookup based on address hash failed"
                        );
                        assert!(
                            bool::from(memo.validate(
                                &sender_addr,
                                &recipient.subaddress_view_private(DEFAULT_SUBADDRESS_INDEX),
                                &output.public_key,
                            )),
                            "hmac validation failed"
                        );
                        assert_eq!(memo.payment_request_id(), 47);
                    }
                }

                // The 2nd output should belong to the correct recipient and have correct amount
                // and have correct memo
                {
                    let memo = validate_amount_and_get_memo(
                        block_version,
                        change,
                        &sender,
                        Amount::new(change_value, token_id),
                    );

                    if block_version.e_memo_feature_is_supported() {
                        assert!(matches!(memo.unwrap(), MemoType::Unused(_)));
                    }
                }
            }

            // Enable destination memo, and set a payment request id, but no sender
            // credential
            {
                let mut memo_builder = RTHMemoBuilder::default();
                memo_builder.enable_destination_memo();
                memo_builder.set_payment_request_id(47);

                let mut transaction_builder = single_input_transaction_builder(
                    block_version,
                    token_id,
                    value,
                    &fog_resolver,
                    &mut rng,
                );

                transaction_builder
                    .add_output(
                        Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                        &recipient_address,
                        &mut rng,
                    )
                    .unwrap();

                transaction_builder
                    .add_change_output(
                        Amount::new(change_value, token_id),
                        &sender_change_dest,
                        &mut rng,
                    )
                    .unwrap();

                let tx = transaction_builder
                    .build(&NoKeysRingSigner {}, memo_builder, &mut rng)
                    .unwrap();

                // The transaction should have two output.
                assert_eq!(tx.prefix.outputs.len(), 2);

                // The tombstone block should be the min of what the user requested, and what
                // fog limits it to
                assert_eq!(tx.prefix.tombstone_block, 1000);

                let output = find_output(&tx, &recipient, DEFAULT_SUBADDRESS_INDEX);
                let change = find_output(&tx, &sender, CHANGE_SUBADDRESS_INDEX);
                validate_tx_outs(
                    block_version,
                    &sender,
                    &[
                        (output, &recipient, DEFAULT_SUBADDRESS_INDEX),
                        (change, &sender, CHANGE_SUBADDRESS_INDEX),
                    ],
                );

                // The 1st output should belong to the correct recipient and have correct amount
                // and have correct memo
                {
                    let memo = validate_amount_and_get_memo(
                        block_version,
                        output,
                        &recipient,
                        Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                    );

                    if block_version.e_memo_feature_is_supported() {
                        assert!(matches!(memo.unwrap(), MemoType::Unused(_)));
                    }
                }

                // The 2nd output should belong to the correct recipient and have correct amount
                // and have correct memo
                {
                    let memo = validate_amount_and_get_memo(
                        block_version,
                        change,
                        &sender,
                        Amount::new(change_value, token_id),
                    );

                    if block_version.e_memo_feature_is_supported() {
                        let MemoType::DestinationWithPaymentRequestId(memo) = memo.unwrap() else {
                            panic!("unexpected memo type")
                        };

                        assert_eq!(
                            memo.get_address_hash(),
                            &ShortAddressHash::from(&recipient_address),
                            "lookup based on address hash failed"
                        );
                        assert_eq!(memo.get_num_recipients(), 1);
                        assert_eq!(memo.get_fee(), Mob::MINIMUM_FEE);
                        assert_eq!(
                            memo.get_total_outlay(),
                            value - change_value,
                            "outlay should be amount sent to recipient + fee"
                        );
                        assert_eq!(memo.get_payment_request_id(), 47);
                    }
                }
            }

            // Enable both sender and destination memos, and set a payment intent id
            {
                let mut memo_builder = RTHMemoBuilder::default();
                memo_builder.set_sender_credential(SenderMemoCredential::from(&sender));
                memo_builder.enable_destination_memo();
                memo_builder.set_payment_intent_id(4855282172840142080);

                let mut transaction_builder = single_input_transaction_builder(
                    block_version,
                    token_id,
                    value,
                    &fog_resolver,
                    &mut rng,
                );

                transaction_builder
                    .add_output(
                        Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                        &recipient_address,
                        &mut rng,
                    )
                    .unwrap();

                transaction_builder
                    .add_change_output(
                        Amount::new(change_value, token_id),
                        &sender_change_dest,
                        &mut rng,
                    )
                    .unwrap();

                let tx = transaction_builder
                    .build(&NoKeysRingSigner {}, memo_builder, &mut rng)
                    .unwrap();

                // The transaction should have two output.
                assert_eq!(tx.prefix.outputs.len(), 2);

                // The tombstone block should be the min of what the user requested, and what
                // fog limits it to
                assert_eq!(tx.prefix.tombstone_block, 1000);

                let output = find_output(&tx, &recipient, DEFAULT_SUBADDRESS_INDEX);
                let change = find_output(&tx, &sender, CHANGE_SUBADDRESS_INDEX);
                validate_tx_outs(
                    block_version,
                    &sender,
                    &[
                        (output, &recipient, DEFAULT_SUBADDRESS_INDEX),
                        (change, &sender, CHANGE_SUBADDRESS_INDEX),
                    ],
                );

                // The 1st output should belong to the correct recipient and have correct amount
                // and have correct memo
                {
                    let memo = validate_amount_and_get_memo(
                        block_version,
                        output,
                        &recipient,
                        Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                    );

                    if block_version.e_memo_feature_is_supported() {
                        let MemoType::AuthenticatedSenderWithPaymentIntentId(memo) = memo.unwrap()
                        else {
                            panic!("unexpected memo type")
                        };

                        assert_eq!(
                            memo.sender_address_hash(),
                            ShortAddressHash::from(&sender_addr),
                            "lookup based on address hash failed"
                        );
                        assert!(
                            bool::from(memo.validate(
                                &sender_addr,
                                &recipient.subaddress_view_private(DEFAULT_SUBADDRESS_INDEX),
                                &output.public_key,
                            )),
                            "hmac validation failed"
                        );
                        assert_eq!(memo.payment_intent_id(), 4855282172840142080);
                    }
                }

                // The 2nd output should belong to the correct recipient and have correct amount
                // and have correct memo
                {
                    let memo = validate_amount_and_get_memo(
                        block_version,
                        change,
                        &sender,
                        Amount::new(change_value, token_id),
                    );

                    if block_version.e_memo_feature_is_supported() {
                        let MemoType::DestinationWithPaymentIntentId(memo) = memo.unwrap() else {
                            panic!("unexpected memo type")
                        };
                        assert_eq!(
                            memo.get_address_hash(),
                            &ShortAddressHash::from(&recipient_address),
                            "lookup based on address hash failed"
                        );
                        assert_eq!(memo.get_num_recipients(), 1);
                        assert_eq!(memo.get_fee(), Mob::MINIMUM_FEE);
                        assert_eq!(
                            memo.get_total_outlay(),
                            value - change_value,
                            "outlay should be amount sent to recipient + fee"
                        );
                        assert_eq!(memo.get_payment_intent_id(), 4855282172840142080);
                    }
                }
            }
        }
    }

    #[test]
    // Transaction builder with RTH memo builder and custom sender credential
    fn test_transaction_builder_memo_custom_sender() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for (block_version, token_id) in get_block_version_token_id_pairs() {
            let alice = AccountKey::random_with_fog(&mut rng);
            let alice_change_dest = ReservedSubaddresses::from(&alice);
            let bob = AccountKey::random_with_fog(&mut rng);
            let bob_address = bob.default_subaddress();
            let charlie = AccountKey::random_with_fog(&mut rng);
            let charlie_addr = charlie.default_subaddress();
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);
            let value = 1475 * MILLIMOB_TO_PICOMOB;
            let change_value = 128 * MILLIMOB_TO_PICOMOB;

            let fog_resolver = MockFogResolver(btreemap! {
                                bob_address
                        .fog_report_url()
                        .unwrap()
                        .to_string()
                =>
                    FullyValidatedFogPubkey {
                        pubkey: RistrettoPublic::from(&ingest_private_key),
                        pubkey_expiry: 1000,
                    },
            });

            // Enable both sender and destination memos, but use a sender credential from
            // Charlie's identity
            {
                let mut memo_builder = RTHMemoBuilder::default();
                memo_builder.set_sender_credential(SenderMemoCredential::from(&charlie));
                memo_builder.enable_destination_memo();

                let mut transaction_builder = single_input_transaction_builder(
                    block_version,
                    token_id,
                    value,
                    &fog_resolver,
                    &mut rng,
                );

                transaction_builder
                    .add_output(
                        Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                        &bob_address,
                        &mut rng,
                    )
                    .unwrap();

                transaction_builder
                    .add_change_output(
                        Amount::new(change_value, token_id),
                        &alice_change_dest,
                        &mut rng,
                    )
                    .unwrap();

                let tx = transaction_builder
                    .build(&NoKeysRingSigner {}, memo_builder, &mut rng)
                    .unwrap();

                // The transaction should have two output.
                assert_eq!(tx.prefix.outputs.len(), 2);

                // The tombstone block should be the min of what the user requested, and what
                // fog limits it to
                assert_eq!(tx.prefix.tombstone_block, 1000);

                let output = find_output(&tx, &bob, DEFAULT_SUBADDRESS_INDEX);
                let change = find_output(&tx, &alice, CHANGE_SUBADDRESS_INDEX);
                validate_tx_outs(
                    block_version,
                    &alice,
                    &[
                        (output, &bob, DEFAULT_SUBADDRESS_INDEX),
                        (change, &alice, CHANGE_SUBADDRESS_INDEX),
                    ],
                );
                assert!(
                    !subaddress_matches_tx_out(&charlie, DEFAULT_SUBADDRESS_INDEX, change).unwrap()
                );
                assert!(
                    !subaddress_matches_tx_out(&charlie, DEFAULT_SUBADDRESS_INDEX, output).unwrap()
                );

                // The 1st output should belong to the correct recipient and have correct amount
                // and have correct memo
                {
                    let memo = validate_amount_and_get_memo(
                        block_version,
                        output,
                        &bob,
                        Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                    );

                    if block_version.e_memo_feature_is_supported() {
                        let MemoType::AuthenticatedSender(memo) = memo.unwrap() else {
                            panic!("unexpected memo type")
                        };
                        assert_eq!(
                            memo.sender_address_hash(),
                            ShortAddressHash::from(&charlie_addr),
                            "lookup based on address hash failed"
                        );
                        assert!(
                            bool::from(memo.validate(
                                &charlie_addr,
                                &bob.subaddress_view_private(DEFAULT_SUBADDRESS_INDEX),
                                &output.public_key,
                            )),
                            "hmac validation failed"
                        );
                    }
                }

                // The 2nd output should belong to the correct recipient and have correct amount
                // and have correct memo
                {
                    let memo = validate_amount_and_get_memo(
                        block_version,
                        change,
                        &alice,
                        Amount::new(change_value, token_id),
                    );

                    if block_version.e_memo_feature_is_supported() {
                        let MemoType::Destination(memo) = memo.unwrap() else {
                            panic!("unexpected memo type")
                        };
                        assert_eq!(
                            memo.get_address_hash(),
                            &ShortAddressHash::from(&bob_address),
                            "lookup based on address hash failed"
                        );
                        assert_eq!(memo.get_num_recipients(), 1);
                        assert_eq!(memo.get_fee(), Mob::MINIMUM_FEE);
                        assert_eq!(
                            memo.get_total_outlay(),
                            value - change_value,
                            "outlay should be amount sent to recipient + fee"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_add_regular_output_after_change_output() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id = TokenId::MOB;
        let block_version = BlockVersion::MAX;
        let sender = AccountKey::random(&mut rng);
        let sender_addr = sender.default_subaddress();
        let sender_change_dest = ReservedSubaddresses::from(&sender);
        let recipient = AccountKey::random(&mut rng);
        let recipient_address = recipient.default_subaddress();
        let value = 1475 * MILLIMOB_TO_PICOMOB;
        let change_value = 128 * MILLIMOB_TO_PICOMOB;
        let fog_resolver = MockFogResolver::default();

        let mut memo_builder = RTHMemoBuilder::default();
        memo_builder.set_sender_credential(SenderMemoCredential::from(&sender));
        memo_builder.enable_destination_memo();

        let mut transaction_builder = single_input_transaction_builder(
            block_version,
            token_id,
            value,
            &fog_resolver,
            &mut rng,
        );

        transaction_builder
            .add_change_output(
                Amount::new(change_value, token_id),
                &sender_change_dest,
                &mut rng,
            )
            .unwrap();

        transaction_builder
            .add_output(
                Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                &recipient_address,
                &mut rng,
            )
            .unwrap();

        let tx = transaction_builder
            .build(&NoKeysRingSigner {}, memo_builder, &mut rng)
            .unwrap();

        assert_eq!(tx.prefix.outputs.len(), 2);

        let output = find_output(&tx, &recipient, DEFAULT_SUBADDRESS_INDEX);
        let change = find_output(&tx, &sender, CHANGE_SUBADDRESS_INDEX);

        // The 1st output should belong to the correct recipient and have correct amount
        // and have correct memo
        {
            let memo = validate_amount_and_get_memo(
                block_version,
                output,
                &recipient,
                Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
            );

            let MemoType::AuthenticatedSender(memo) = memo.unwrap() else {
                panic!("unexpected memo type")
            };

            assert_eq!(
                memo.sender_address_hash(),
                ShortAddressHash::from(&sender_addr),
                "lookup based on address hash failed"
            );
            assert!(
                bool::from(memo.validate(
                    &sender_addr,
                    &recipient.subaddress_view_private(DEFAULT_SUBADDRESS_INDEX),
                    &output.public_key,
                )),
                "hmac validation failed"
            );
        }

        // The 2nd output should belong to the correct recipient and have correct amount
        // and have correct memo
        {
            let memo = validate_amount_and_get_memo(
                block_version,
                change,
                &sender,
                Amount::new(change_value, token_id),
            );
            let MemoType::Destination(memo) = memo.unwrap() else {
                panic!("unexpected memo type")
            };
            assert_eq!(
                memo.get_address_hash(),
                &ShortAddressHash::from(&recipient_address),
                "lookup based on address hash failed"
            );
            assert_eq!(memo.get_num_recipients(), 1);
            assert_eq!(memo.get_fee(), Mob::MINIMUM_FEE);
            assert_eq!(
                memo.get_total_outlay(),
                value - change_value,
                "outlay should be amount sent to recipient + fee"
            );
        }
    }

    #[test]
    // TransactionBuilder with RTHMemoBuilder expected failures due to modification
    // after change output
    fn transaction_builder_rth_memo_expected_failures() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for (block_version, token_id) in get_block_version_token_id_pairs() {
            if !block_version.e_memo_feature_is_supported() {
                continue;
            }

            let sender = AccountKey::random_with_fog(&mut rng);
            let sender_change_dest = ReservedSubaddresses::from(&sender);
            let recipient = AccountKey::random_with_fog(&mut rng);
            let recipient_address = recipient.default_subaddress();
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);
            let value = 1475 * MILLIMOB_TO_PICOMOB;
            let change_value = 128 * MILLIMOB_TO_PICOMOB;

            let fog_resolver = MockFogResolver(btreemap! {
                                recipient_address
                        .fog_report_url()
                        .unwrap()
                        .to_string()
                =>
                    FullyValidatedFogPubkey {
                        pubkey: RistrettoPublic::from(&ingest_private_key),
                        pubkey_expiry: 1000,
                    },
            });

            // Multiple change outputs cause error
            {
                let mut memo_builder = RTHMemoBuilder::default();
                memo_builder.set_sender_credential(SenderMemoCredential::from(&sender));
                memo_builder.enable_destination_memo();

                let mut transaction_builder = single_input_transaction_builder(
                    block_version,
                    token_id,
                    value,
                    &fog_resolver,
                    &mut rng,
                );

                transaction_builder
                    .add_output(
                        Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                        &recipient_address,
                        &mut rng,
                    )
                    .unwrap();

                transaction_builder
                    .add_change_output(
                        Amount::new(change_value, token_id),
                        &sender_change_dest,
                        &mut rng,
                    )
                    .unwrap();

                transaction_builder
                    .add_change_output(
                        Amount::new(change_value, token_id),
                        &sender_change_dest,
                        &mut rng,
                    )
                    .unwrap();

                let result =
                    transaction_builder.build(&NoKeysRingSigner {}, memo_builder, &mut rng);

                assert_matches!(
                    result,
                    Err(TxBuilderError::NewTx(NewTxError::Memo(
                        NewMemoError::MultipleChangeOutputs
                    )))
                );
            }
        }
    }

    #[test]
    #[ignore]
    // `build` should return an error if the inputs contain rings of different
    // sizes.
    fn test_inputs_with_different_ring_sizes() {
        unimplemented!()
    }

    #[test]
    // `build` should return an error if the sum of inputs does not equal the sum of
    // outputs and the fee.
    fn test_inputs_do_not_equal_outputs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for (block_version, token_id) in get_block_version_token_id_pairs() {
            let fpr = MockFogResolver::default();
            let bob = AccountKey::random(&mut rng);
            let value = 1475;

            let mut transaction_builder =
                single_input_transaction_builder(block_version, token_id, value, &fpr, &mut rng);

            let wrong_value = 999;
            transaction_builder
                .add_output(
                    Amount::new(wrong_value, token_id),
                    &bob.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            let result =
                transaction_builder.build(&NoKeysRingSigner {}, EmptyMemoBuilder, &mut rng);
            // Signing should fail if value is not conserved.
            match result {
                Err(TxBuilderError::RingSignatureFailed(_)) => {} // Expected.
                _ => panic!("Unexpected result {result:?}"),
            }
        }
    }

    #[test]
    // `build` should succeed with MAX_INPUTS and MAX_OUTPUTS.
    fn test_max_transaction_size() {
        let mut rng: StdRng = SeedableRng::from_seed([18u8; 32]);

        for (block_version, token_id) in get_block_version_token_id_pairs() {
            let fpr = MockFogResolver::default();
            let sender = AccountKey::random(&mut rng);
            let recipient = AccountKey::random(&mut rng);
            let tx = get_transaction(
                block_version,
                token_id,
                MAX_INPUTS as usize,
                MAX_OUTPUTS as usize,
                &sender,
                &recipient,
                fpr,
                &mut rng,
            )
            .unwrap();
            assert_eq!(tx.prefix.inputs.len(), MAX_INPUTS as usize);
            assert_eq!(tx.prefix.outputs.len(), MAX_OUTPUTS as usize);
        }
    }

    #[test]
    // Ring elements should be sorted by tx_out.public_key
    fn test_ring_elements_are_sorted() {
        let mut rng: StdRng = SeedableRng::from_seed([97u8; 32]);

        for (block_version, token_id) in get_block_version_token_id_pairs() {
            let fpr = MockFogResolver::default();
            let sender = AccountKey::random(&mut rng);
            let recipient = AccountKey::random(&mut rng);
            let num_inputs = 3;
            let num_outputs = 11;
            let tx = get_transaction(
                block_version,
                token_id,
                num_inputs,
                num_outputs,
                &sender,
                &recipient,
                fpr,
                &mut rng,
            )
            .unwrap();

            for tx_in in &tx.prefix.inputs {
                assert!(tx_in
                    .ring
                    .windows(2)
                    .all(|w| w[0].public_key < w[1].public_key));
            }
        }
    }

    #[test]
    // Transaction outputs should be sorted by public key.
    fn test_outputs_are_sorted() {
        let mut rng: StdRng = SeedableRng::from_seed([92u8; 32]);

        for (block_version, token_id) in get_block_version_token_id_pairs() {
            let fpr = MockFogResolver::default();
            let sender = AccountKey::random(&mut rng);
            let recipient = AccountKey::random(&mut rng);
            let num_inputs = 3;
            let num_outputs = 11;
            let tx = get_transaction(
                block_version,
                token_id,
                num_inputs,
                num_outputs,
                &sender,
                &recipient,
                fpr,
                &mut rng,
            )
            .unwrap();

            let outputs = tx.prefix.outputs;
            let mut expected_outputs = outputs.clone();
            expected_outputs.sort_by(|a, b| a.public_key.cmp(&b.public_key));
            assert_eq!(outputs, expected_outputs);
        }
    }

    #[test]
    // Transaction inputs should be sorted by the public key of the first ring
    // element.
    fn test_inputs_are_sorted() {
        let mut rng: StdRng = SeedableRng::from_seed([92u8; 32]);

        for (block_version, token_id) in get_block_version_token_id_pairs() {
            let fpr = MockFogResolver::default();
            let sender = AccountKey::random(&mut rng);
            let recipient = AccountKey::random(&mut rng);
            let num_inputs = 3;
            let num_outputs = 11;
            let tx = get_transaction(
                block_version,
                token_id,
                num_inputs,
                num_outputs,
                &sender,
                &recipient,
                fpr,
                &mut rng,
            )
            .unwrap();

            let inputs = tx.prefix.inputs;
            let mut expected_inputs = inputs.clone();
            expected_inputs.sort_by(|a, b| a.ring[0].public_key.cmp(&b.ring[0].public_key));
            assert_eq!(inputs, expected_inputs);
        }
    }

    #[test]
    // Test that sending money to a burn address works, and that view key scanning
    // reveals the amount correctly.
    fn test_burn_address() {
        let mut rng: StdRng = SeedableRng::from_seed([18u8; 32]);

        let block_version = BlockVersion::MAX;

        let fog_resolver = MockFogResolver::default();
        let sender = AccountKey::random(&mut rng);
        let sender_change_dest = ReservedSubaddresses::from(&sender);
        let recipient = burn_address();

        let value = 1475 * MILLIMOB_TO_PICOMOB;
        let change_value = 128 * MILLIMOB_TO_PICOMOB;

        let token_id = Mob::ID;

        for _ in 0..3 {
            let mut memo_builder = RTHMemoBuilder::default();
            memo_builder.set_sender_credential(SenderMemoCredential::from(&sender));
            memo_builder.enable_destination_memo();

            let mut transaction_builder = single_input_transaction_builder(
                block_version,
                token_id,
                value,
                &fog_resolver,
                &mut rng,
            );

            let TxOutContext {
                tx_out_public_key: burn_tx_out_public_key,
                ..
            } = transaction_builder
                .add_output(
                    Amount::new(value - change_value - Mob::MINIMUM_FEE, token_id),
                    &recipient,
                    &mut rng,
                )
                .unwrap();

            transaction_builder
                .add_change_output(
                    Amount::new(change_value, token_id),
                    &sender_change_dest,
                    &mut rng,
                )
                .unwrap();

            let tx = transaction_builder
                .build(&NoKeysRingSigner {}, memo_builder, &mut rng)
                .unwrap();

            assert_eq!(tx.prefix.outputs.len(), 2);
            let idx = tx
                .prefix
                .outputs
                .iter()
                .position(|tx_out| tx_out.public_key == burn_tx_out_public_key)
                .unwrap();
            let change_idx = 1 - idx;

            let burn_tx_out = &tx.prefix.outputs[idx];
            let change_tx_out = &tx.prefix.outputs[change_idx];

            // Test that sender's change subaddress owns the change, and not the burn tx out
            assert!(
                !subaddress_matches_tx_out(&sender, CHANGE_SUBADDRESS_INDEX, burn_tx_out).unwrap()
            );
            assert!(
                subaddress_matches_tx_out(&sender, CHANGE_SUBADDRESS_INDEX, change_tx_out).unwrap()
            );

            // Test that view key matching works with the burn tx out with burn address view
            // key
            let (amount, _) = burn_tx_out
                .view_key_match(&burn_address_view_private())
                .unwrap();
            assert_eq!(amount.value, value - change_value - Mob::MINIMUM_FEE);

            assert!(change_tx_out
                .view_key_match(&burn_address_view_private())
                .is_err());

            // Test that view key matching works with the change tx out with sender's view
            // key
            let (amount, _) = change_tx_out
                .view_key_match(sender.view_private_key())
                .unwrap();
            assert_eq!(amount.value, change_value);

            assert!(burn_tx_out
                .view_key_match(sender.view_private_key())
                .is_err());
        }
    }

    #[test]
    // Transaction builder with Burn Redemption memo builder
    fn test_transaction_builder_burn_redemption_memos() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let block_version = BlockVersion::MAX;
        let token_id = TokenId::from(5);
        let fog_resolver = MockFogResolver::default();
        let sender = AccountKey::random(&mut rng);
        let change_destination = ReservedSubaddresses::from(&sender);

        let transaction_builder =
            single_input_transaction_builder(block_version, token_id, 500, &fog_resolver, &mut rng);

        // Adding an output that is not to the burn address is not allowed.
        {
            let memo_builder = BurnRedemptionMemoBuilder::new([2u8; 64]);
            let mut transaction_builder = transaction_builder.clone();

            let recipient = AccountKey::random(&mut rng);
            transaction_builder
                .add_output(
                    Amount::new(100, token_id),
                    &recipient.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            let result = transaction_builder.build(&NoKeysRingSigner {}, memo_builder, &mut rng);

            assert_matches!(
                result,
                Err(TxBuilderError::NewTx(NewTxError::Memo(
                    NewMemoError::InvalidRecipient
                )))
            );
        }

        // Adding two burn outputs is not allowed.
        {
            let memo_builder = BurnRedemptionMemoBuilder::new([2u8; 64]);
            let mut transaction_builder = transaction_builder.clone();

            transaction_builder
                .add_output(Amount::new(100, token_id), &burn_address(), &mut rng)
                .unwrap();

            transaction_builder
                .add_output(Amount::new(100, token_id), &burn_address(), &mut rng)
                .unwrap();

            let result = transaction_builder.build(&NoKeysRingSigner {}, memo_builder, &mut rng);
            assert_matches!(
                result,
                Err(TxBuilderError::NewTx(NewTxError::Memo(
                    NewMemoError::MultipleOutputs
                )))
            );
        }

        // Adding a change output before a burn output is not allowed.
        {
            let mut memo_builder = BurnRedemptionMemoBuilder::new([2u8; 64]);
            memo_builder.enable_destination_memo();

            let mut transaction_builder = transaction_builder.clone();

            transaction_builder
                .add_change_output(Amount::new(10, token_id), &change_destination, &mut rng)
                .unwrap();

            let result = transaction_builder.build(&NoKeysRingSigner {}, memo_builder, &mut rng);

            assert_matches!(
                result,
                Err(TxBuilderError::NewTx(NewTxError::Memo(
                    NewMemoError::MissingOutput
                )))
            );
        }

        // Change in a different token is not allowed.
        {
            let mut memo_builder = BurnRedemptionMemoBuilder::new([3u8; 64]);
            memo_builder.enable_destination_memo();

            let mut transaction_builder = transaction_builder.clone();

            transaction_builder
                .add_output(Amount::new(490, Mob::ID), &burn_address(), &mut rng)
                .unwrap();

            transaction_builder
                .add_change_output(Amount::new(10, Mob::ID), &change_destination, &mut rng)
                .unwrap();

            let result = transaction_builder.build(&NoKeysRingSigner {}, memo_builder, &mut rng);

            assert_matches!(
                result,
                Err(TxBuilderError::NewTx(NewTxError::Memo(
                    NewMemoError::MixedTokenIds
                )))
            );
        }

        // Happy flow without change
        {
            let mut memo_builder = BurnRedemptionMemoBuilder::new([2u8; 64]);
            memo_builder.enable_destination_memo();

            let mut transaction_builder = transaction_builder.clone();
            transaction_builder.set_fee(3).unwrap();

            let TxOutContext {
                tx_out_public_key: burn_output_public_key,
                ..
            } = transaction_builder
                .add_output(Amount::new(497, token_id), &burn_address(), &mut rng)
                .unwrap();

            let tx = transaction_builder
                .build(&NoKeysRingSigner {}, memo_builder, &mut rng)
                .expect("build tx");

            assert_eq!(tx.prefix.outputs.len(), 1);
            assert_eq!(burn_output_public_key, tx.prefix.outputs[0].public_key);
            let burn_output = &tx.prefix.outputs[0];

            // Test that view key matching works with the burn tx out with burn address view
            // key
            let (amount, _) = burn_output
                .view_key_match(&burn_address_view_private())
                .unwrap();
            assert_eq!(amount, Amount::new(497, token_id));

            // Burn output should have a burn redemption memo
            let ss = get_tx_out_shared_secret(
                &burn_address_view_private(),
                &RistrettoPublic::try_from(&burn_output.public_key).unwrap(),
            );
            let memo = burn_output.e_memo.unwrap().decrypt(&ss);
            match MemoType::try_from(&memo).expect("Couldn't decrypt memo") {
                MemoType::BurnRedemption(memo) => {
                    assert_eq!(memo.memo_data(), &[2u8; 64],);
                }
                _ => {
                    panic!("unexpected memo type")
                }
            }
        }

        // Happy flow with change
        {
            let mut memo_builder = BurnRedemptionMemoBuilder::new([3u8; 64]);
            memo_builder.enable_destination_memo();

            let mut transaction_builder = transaction_builder.clone();

            transaction_builder.set_fee(3).unwrap();

            let TxOutContext {
                tx_out_public_key: burn_tx_out_public_key,
                ..
            } = transaction_builder
                .add_output(Amount::new(100, token_id), &burn_address(), &mut rng)
                .unwrap();

            let change_amount = 500 - 100 - 3;
            transaction_builder
                .add_change_output(
                    Amount::new(change_amount, token_id),
                    &change_destination,
                    &mut rng,
                )
                .unwrap();

            let tx = transaction_builder
                .build(&NoKeysRingSigner {}, memo_builder, &mut rng)
                .expect("build tx");

            assert_eq!(tx.prefix.outputs.len(), 2);

            let burn_output = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| tx_out.public_key == burn_tx_out_public_key)
                .expect("Didn't find recipient's output");
            let change_output = find_output(&tx, &sender, CHANGE_SUBADDRESS_INDEX);

            // Test that view key matching works with the burn tx out with burn address view
            // key
            let (amount, _) = burn_output
                .view_key_match(&burn_address_view_private())
                .unwrap();
            assert_eq!(amount, Amount::new(100, token_id));

            assert!(change_output
                .view_key_match(&burn_address_view_private())
                .is_err());

            // Test that view key matching works with the change tx out with sender's view
            // key
            let (amount, _) = change_output
                .view_key_match(sender.view_private_key())
                .unwrap();
            assert_eq!(amount, Amount::new(change_amount, token_id));

            assert!(burn_output
                .view_key_match(sender.view_private_key())
                .is_err());

            // Burn output should have a burn redemption memo
            let ss = get_tx_out_shared_secret(
                &burn_address_view_private(),
                &RistrettoPublic::try_from(&burn_output.public_key).unwrap(),
            );
            let memo = burn_output.e_memo.unwrap().decrypt(&ss);
            match MemoType::try_from(&memo).expect("Couldn't decrypt memo") {
                MemoType::BurnRedemption(memo) => {
                    assert_eq!(memo.memo_data(), &[3u8; 64],);
                }
                _ => {
                    panic!("unexpected memo type")
                }
            }

            // Change output should have a destination memo
            let memo = validate_amount_and_get_memo(
                block_version,
                change_output,
                &sender,
                Amount::new(change_amount, token_id),
            );

            let MemoType::Destination(memo) = memo.unwrap() else {
                panic!("unexpected memo type")
            };
            assert_eq!(
                memo.get_address_hash(),
                &ShortAddressHash::from(&burn_address()),
                "lookup based on address hash failed"
            );
            assert_eq!(memo.get_num_recipients(), 1);
            assert_eq!(memo.get_fee(), 3);
            assert_eq!(
                memo.get_total_outlay(),
                103,
                "outlay should be amount sent to recipient + fee"
            );
        }
    }

    #[test]
    // Test that sending mixed transactions works
    //
    // This test uses inputs of two different token IDs, paying the fee and creating
    // change with TokenID1, and "passing through" the second token ID with its
    // full amount as output.
    fn test_mixed_transactions() {
        let mut rng: StdRng = SeedableRng::from_seed([18u8; 32]);

        let fog_resolver = MockFogResolver::default();
        let sender = AccountKey::random(&mut rng);
        let sender_change_dest = ReservedSubaddresses::from(&sender);
        let recipient = AccountKey::random(&mut rng);
        let recipient_addr = recipient.default_subaddress();

        let amount1 = Amount::new(1475 * MILLIMOB_TO_PICOMOB, Mob::ID);
        let change_amount = Amount::new(128 * MILLIMOB_TO_PICOMOB, Mob::ID);
        let amount2 = Amount::new(999999, 2.into());

        let tx_out1_right_amount = Amount::new(
            amount1.value - change_amount.value - Mob::MINIMUM_FEE,
            Mob::ID,
        );

        for block_version in 3..=*BlockVersion::MAX {
            let block_version = BlockVersion::try_from(block_version).unwrap();
            let memo_builder = EmptyMemoBuilder;

            let mut transaction_builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, Mob::ID),
                fog_resolver.clone(),
            )
            .unwrap();

            let input_credentials =
                get_input_credentials(block_version, amount1, &sender, &fog_resolver, &mut rng);
            transaction_builder.add_input(input_credentials);

            let input_credentials =
                get_input_credentials(block_version, amount2, &sender, &fog_resolver, &mut rng);
            transaction_builder.add_input(input_credentials);

            let tx_out_context1 = transaction_builder
                .add_output(tx_out1_right_amount, &recipient_addr, &mut rng)
                .unwrap();

            let tx_out_context2 = transaction_builder
                .add_output(amount2, &recipient_addr, &mut rng)
                .unwrap();

            transaction_builder
                .add_change_output(change_amount, &sender_change_dest, &mut rng)
                .unwrap();

            let tx = transaction_builder
                .build(&NoKeysRingSigner {}, memo_builder, &mut rng)
                .unwrap();

            assert_eq!(tx.prefix.outputs.len(), 3);
            let idx1 = tx
                .prefix
                .outputs
                .iter()
                .position(|tx_out| tx_out.public_key == tx_out_context1.tx_out_public_key)
                .unwrap();
            let idx2 = tx
                .prefix
                .outputs
                .iter()
                .position(|tx_out| tx_out.public_key == tx_out_context2.tx_out_public_key)
                .unwrap();
            let change_idx = (0..3).find(|x| *x != idx1 && *x != idx2).unwrap();

            let tx_out1 = &tx.prefix.outputs[idx1];
            let tx_out2 = &tx.prefix.outputs[idx2];
            let change_tx_out = &tx.prefix.outputs[change_idx];

            // Test that sender's change subaddress owns the change, and not the other tx
            // outs
            assert!(!subaddress_matches_tx_out(&sender, CHANGE_SUBADDRESS_INDEX, tx_out1).unwrap());
            assert!(!subaddress_matches_tx_out(&sender, CHANGE_SUBADDRESS_INDEX, tx_out2).unwrap());
            assert!(
                subaddress_matches_tx_out(&sender, CHANGE_SUBADDRESS_INDEX, change_tx_out).unwrap()
            );

            // Test that recipients's default subaddress owns the correct output, and not
            // the other tx outs
            assert!(
                subaddress_matches_tx_out(&recipient, DEFAULT_SUBADDRESS_INDEX, tx_out1).unwrap()
            );
            assert!(
                subaddress_matches_tx_out(&recipient, DEFAULT_SUBADDRESS_INDEX, tx_out2).unwrap()
            );
            assert!(!subaddress_matches_tx_out(
                &recipient,
                DEFAULT_SUBADDRESS_INDEX,
                change_tx_out
            )
            .unwrap());

            // Test that view key matching works with the two tx outs
            let (amount, _) = tx_out1
                .view_key_match(recipient.view_private_key())
                .unwrap();
            assert_eq!(
                amount.value,
                amount1.value - change_amount.value - Mob::MINIMUM_FEE
            );
            assert_eq!(amount.token_id, Mob::ID);

            let (amount, _) = tx_out2
                .view_key_match(recipient.view_private_key())
                .unwrap();
            assert_eq!(amount, amount2);

            assert!(change_tx_out
                .view_key_match(recipient.view_private_key())
                .is_err());

            // Test that view key matching works with the change tx out with sender's view
            // key
            let (amount, _) = change_tx_out
                .view_key_match(sender.view_private_key())
                .unwrap();
            assert_eq!(amount.value, change_amount.value);

            assert!(tx_out1.view_key_match(sender.view_private_key()).is_err());

            assert!(tx_out2.view_key_match(sender.view_private_key()).is_err());
        }
    }

    #[test]
    // Test mixed transactions expected failures (imbalanced transactions)
    fn test_mixed_transactions_expected_failure_imbalanced_transactions() {
        let mut rng: StdRng = SeedableRng::from_seed([18u8; 32]);

        let fog_resolver = MockFogResolver::default();
        let sender = AccountKey::random(&mut rng);
        let sender_change_dest = ReservedSubaddresses::from(&sender);
        let recipient = AccountKey::random(&mut rng);
        let recipient_addr = recipient.default_subaddress();

        let amount1 = Amount::new(1475 * MILLIMOB_TO_PICOMOB, Mob::ID);
        let change_amount = Amount::new(128 * MILLIMOB_TO_PICOMOB, Mob::ID);
        let amount2 = Amount::new(999999, 2.into());

        let tx_out1_right_amount = Amount::new(
            amount1.value - change_amount.value - Mob::MINIMUM_FEE,
            Mob::ID,
        );

        // Builds a transaction using a particular amount in place of tx_out1, returning
        // result of `.build()`
        let mut test_fn = |block_version, tx_out1_amount| -> Result<_, _> {
            let memo_builder = EmptyMemoBuilder;

            let mut transaction_builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, Mob::ID),
                fog_resolver.clone(),
            )
            .unwrap();

            let input_credentials =
                get_input_credentials(block_version, amount1, &sender, &fog_resolver, &mut rng);
            transaction_builder.add_input(input_credentials);

            let input_credentials =
                get_input_credentials(block_version, amount2, &sender, &fog_resolver, &mut rng);
            transaction_builder.add_input(input_credentials);

            transaction_builder
                .add_output(tx_out1_amount, &recipient_addr, &mut rng)
                .unwrap();

            transaction_builder
                .add_output(amount2, &recipient_addr, &mut rng)
                .unwrap();

            transaction_builder
                .add_change_output(change_amount, &sender_change_dest, &mut rng)
                .unwrap();

            transaction_builder.build(&NoKeysRingSigner {}, memo_builder, &mut rng)
        };

        for block_version in 3..=*BlockVersion::MAX {
            let block_version = BlockVersion::try_from(block_version).unwrap();

            assert!(test_fn(block_version, tx_out1_right_amount).is_ok());

            let mut tx_out1_wrong_amount = tx_out1_right_amount;
            tx_out1_wrong_amount.value -= 1;
            assert!(test_fn(block_version, tx_out1_wrong_amount).is_err());

            tx_out1_wrong_amount.value += 2;
            assert!(test_fn(block_version, tx_out1_wrong_amount).is_err());

            tx_out1_wrong_amount.token_id = 99.into();
            assert!(test_fn(block_version, tx_out1_wrong_amount).is_err());

            tx_out1_wrong_amount.value -= 1;
            assert!(test_fn(block_version, tx_out1_wrong_amount).is_err());
        }
    }

    #[test]
    // Transaction builder with gift codes
    fn test_gift_code_transactions() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let block_version = BlockVersion::MAX;
        let token_id = TokenId::from(5);
        let fog_resolver = MockFogResolver::default();
        let sender = AccountKey::random(&mut rng);
        let receiver = AccountKey::random(&mut rng);
        let (funding_input_amt, funding_output_amt, fee) = (1000, 10, 1);
        let sender_reserved_destinations = ReservedSubaddresses::from(&sender);
        let receiver_reserved_destinations = ReservedSubaddresses::from(&receiver);
        let note = "It's funding time";

        // Test gift code funding and sending
        {
            // Initialize funding memo & transaction builders
            let funding_memo_builder = GiftCodeFundingMemoBuilder::new(note).unwrap();
            let funding_output_amount = Amount::new(funding_output_amt, token_id);
            let funding_change_output_amount =
                Amount::new(funding_input_amt - funding_output_amt - fee, token_id);
            let mut funding_transaction_builder = single_input_transaction_builder(
                block_version,
                token_id,
                funding_input_amt,
                &fog_resolver,
                &mut rng,
            );
            funding_transaction_builder.set_fee(fee).unwrap();

            // Fund gift code TxOut
            funding_transaction_builder
                .add_gift_code_output(
                    funding_output_amount,
                    &sender_reserved_destinations,
                    &mut rng,
                )
                .unwrap();

            funding_transaction_builder
                .add_change_output(
                    funding_change_output_amount,
                    &sender_reserved_destinations,
                    &mut rng,
                )
                .unwrap();

            let funding_tx = funding_transaction_builder
                .build(&NoKeysRingSigner {}, funding_memo_builder, &mut rng)
                .unwrap();

            // The transaction should have exactly 2 outputs
            assert_eq!(funding_tx.prefix.outputs.len(), 2);

            let funding_output = find_output(&funding_tx, &sender, GIFT_CODE_SUBADDRESS_INDEX);
            let funding_change_output = find_output(&funding_tx, &sender, CHANGE_SUBADDRESS_INDEX);

            validate_tx_out(block_version, funding_output).unwrap();
            validate_tx_out(block_version, funding_change_output).unwrap();

            // Ensure funding output & change memos are correct
            let funding_output_public_key =
                &RistrettoPublic::try_from(&funding_output.public_key).unwrap();
            let funding_change_output_tx_out_public_key =
                &RistrettoPublic::try_from(&funding_change_output.public_key).unwrap();
            let funding_output_ss =
                get_tx_out_shared_secret(sender.view_private_key(), funding_output_public_key);
            let funding_change_output_ss = get_tx_out_shared_secret(
                sender.view_private_key(),
                funding_change_output_tx_out_public_key,
            );

            let (funding_amount, _) = funding_output
                .get_masked_amount()
                .unwrap()
                .get_value(&funding_output_ss)
                .unwrap();
            assert_eq!(funding_amount.value, funding_output_amount.value);
            assert_eq!(funding_amount.token_id, token_id);

            if block_version.e_memo_feature_is_supported() {
                let funding_change_output_memo = funding_change_output
                    .e_memo
                    .unwrap()
                    .decrypt(&funding_change_output_ss);
                let funding_output_memo =
                    funding_output.e_memo.unwrap().decrypt(&funding_output_ss);
                match MemoType::try_from(&funding_change_output_memo)
                    .expect("Couldn't decrypt funding change memo")
                {
                    MemoType::GiftCodeFunding(memo) => {
                        assert!(memo.public_key_matches(funding_output_public_key),);
                        assert_eq!(memo.funding_note().unwrap(), note,);
                    }
                    _ => {
                        panic!("unexpected memo type")
                    }
                };
                assert_matches!(
                    MemoType::try_from(&funding_output_memo),
                    Ok(MemoType::Unused(_))
                );
            }

            // MCIP #32 specifies that the receiver will receive the TxOut index,
            // shared_secret and onetime_private_key in a message. Below we
            // simulate a receiver sending the gift code to themselves with the
            // those 3 pieces of information from the gift code TxOut funded above

            // Get the data we're pretending sender sends to the receiver and
            // construct TxOutGiftCode object from it. This data would
            // normally be sent via a protobuf message
            let global_index = 42;
            let gift_code_tx_out_private_key = recover_onetime_private_key(
                funding_output_public_key,
                sender.view_private_key(),
                &sender.gift_code_subaddress_spend_private(),
            );
            let tx_out_gift_code = TxOutGiftCode {
                global_index,
                onetime_private_key: gift_code_tx_out_private_key,
                shared_secret: funding_output_ss,
            };

            // Values we pretend we get from locating the TxOut using the global index
            let masked_amount = funding_output.get_masked_amount().unwrap().clone();

            // Construct the sender Tx from the combo of "located" and "sent" information
            let (sending_input_amount, blinding) = masked_amount
                .get_value(&tx_out_gift_code.shared_secret)
                .unwrap();
            let sending_output_amount = Amount::new(sending_input_amount.value - fee, token_id);

            let ring_size = 3;
            let mut ring: Vec<TxOut> = Vec::new();
            for idx in 0..ring_size - 1 {
                let address = AccountKey::random(&mut rng).default_subaddress();
                let mixed_token_id = if block_version.masked_token_id_feature_is_supported() {
                    TokenId::from(idx as u64)
                } else {
                    token_id
                };
                let amount = Amount::new(sending_output_amount.value, mixed_token_id);
                let (tx_out, _) =
                    create_output(block_version, amount, &address, &fog_resolver, &mut rng)
                        .unwrap();
                ring.push(tx_out);
            }

            let real_index = (rng.next_u64() % ring_size as u64) as usize;
            ring.insert(real_index, funding_output.clone());
            assert_eq!(ring.len(), ring_size);

            let membership_proofs: Vec<TxOutMembershipProof> = ring
                .iter()
                .map(|_tx_out| TxOutMembershipProof::default())
                .collect();

            // Construct our sending memo builder
            let note = "It's sending time";
            let sending_memo_builder = GiftCodeSenderMemoBuilder::new(note).unwrap();

            let mut transaction_builder = TransactionBuilder::new(
                block_version,
                Amount::new(fee, token_id),
                fog_resolver.clone(),
            )
            .unwrap();

            // Create our inputs from reconstructed info
            let input_credentials = InputCredentials {
                ring,
                membership_proofs,
                real_index,
                input_secret: InputSecret {
                    onetime_key_derive_data: gift_code_tx_out_private_key.into(),
                    amount: sending_input_amount,
                    blinding,
                },
            };

            transaction_builder.add_input(input_credentials);

            // Add the output and build the transaction
            transaction_builder
                .add_change_output(
                    sending_output_amount,
                    &receiver_reserved_destinations,
                    &mut rng,
                )
                .unwrap();

            let tx = transaction_builder
                .build(&NoKeysRingSigner {}, sending_memo_builder, &mut rng)
                .unwrap();

            // Verify the sender transaction was valid
            assert_eq!(tx.prefix.outputs.len(), 1);

            let change = find_output(&tx, &receiver, CHANGE_SUBADDRESS_INDEX);

            validate_tx_out(block_version, change).unwrap();

            // Ensure change memo is correct
            let memo = validate_amount_and_get_memo(
                block_version,
                change,
                &receiver,
                Amount::new(sending_output_amount.value, token_id),
            );

            if block_version.e_memo_feature_is_supported() {
                let MemoType::GiftCodeSender(memo) = memo.unwrap() else {
                    panic!("unexpected memo type")
                };
                assert_eq!(memo.sender_note().unwrap(), note);
            }
        }

        // Test gift code cancellation
        {
            let sample_index = 1;
            let cancellation_memo_builder = GiftCodeCancellationMemoBuilder::new(sample_index);

            let cancellation_output_amount = Amount::new(funding_output_amt - fee, token_id);

            let mut transaction_builder = single_input_transaction_builder(
                block_version,
                token_id,
                funding_output_amt,
                &fog_resolver,
                &mut rng,
            );
            transaction_builder.set_fee(fee).unwrap();

            // Cancel gift code
            transaction_builder
                .add_change_output(
                    cancellation_output_amount,
                    &sender_reserved_destinations,
                    &mut rng,
                )
                .unwrap();

            let tx = transaction_builder
                .build(&NoKeysRingSigner {}, cancellation_memo_builder, &mut rng)
                .unwrap();

            // The transaction should have exactly 1 output
            assert_eq!(tx.prefix.outputs.len(), 1);

            let change = find_output(&tx, &sender, CHANGE_SUBADDRESS_INDEX);

            validate_tx_out(block_version, change).unwrap();

            // Ensure change memo is correct
            let memo = validate_amount_and_get_memo(
                block_version,
                change,
                &sender,
                Amount::new(cancellation_output_amount.value, token_id),
            );

            if block_version.e_memo_feature_is_supported() {
                let MemoType::GiftCodeCancellation(memo) = memo.unwrap() else {
                    panic!("unexpected memo type")
                };
                assert_eq!(memo.cancelled_gift_code_index(), sample_index);
            }
        }
    }

    #[test]
    // Test errors in gift code building
    fn test_gift_code_transaction_builder_errors() {
        // Test funding multiple gift at once codes fails
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let sender_reserved_destinations = ReservedSubaddresses::from(&sender);
        let token_id = TokenId::from(5);
        let note = "I'm a note";

        // Ensure we can't do more than one gift code TxOut output
        {
            let funding_memo_builder = GiftCodeFundingMemoBuilder::new(note).unwrap();

            let mut transaction_builder = single_input_transaction_builder(
                BlockVersion::MAX,
                token_id,
                100,
                &MockFogResolver::default(),
                &mut rng,
            );

            transaction_builder
                .add_output(
                    Amount::new(100, token_id),
                    &sender_reserved_destinations.gift_code_subaddress,
                    &mut rng,
                )
                .unwrap();

            transaction_builder
                .add_output(
                    Amount::new(100, token_id),
                    &sender_reserved_destinations.gift_code_subaddress,
                    &mut rng,
                )
                .unwrap();

            let result =
                transaction_builder.build(&NoKeysRingSigner {}, funding_memo_builder, &mut rng);
            assert_matches!(
                result,
                Err(TxBuilderError::NewTx(NewTxError::Memo(
                    NewMemoError::MultipleOutputs
                )))
            );
        }

        // Ensure we can't write change before funding
        {
            let funding_memo_builder = GiftCodeFundingMemoBuilder::new(note).unwrap();

            let mut transaction_builder = single_input_transaction_builder(
                BlockVersion::MAX,
                token_id,
                100,
                &MockFogResolver::default(),
                &mut rng,
            );

            // Try to write change before funding gift code and assert it errors
            transaction_builder
                .add_change_output(
                    Amount::new(100, token_id),
                    &sender_reserved_destinations,
                    &mut rng,
                )
                .unwrap();

            let result =
                transaction_builder.build(&NoKeysRingSigner {}, funding_memo_builder, &mut rng);

            assert_matches!(
                result,
                Err(TxBuilderError::NewTx(NewTxError::Memo(
                    NewMemoError::MissingOutput
                )))
            );
        }

        // Ensure we can't add two outputs
        {
            let funding_memo_builder = GiftCodeFundingMemoBuilder::new(note).unwrap();

            let mut transaction_builder = single_input_transaction_builder(
                BlockVersion::MAX,
                token_id,
                100,
                &MockFogResolver::default(),
                &mut rng,
            );

            transaction_builder
                .add_output(
                    Amount::new(100, token_id),
                    &sender_reserved_destinations.gift_code_subaddress,
                    &mut rng,
                )
                .unwrap();

            // Attempt to fund second gift code, this will trigger an error when we build
            transaction_builder
                .add_output(
                    Amount::new(100, token_id),
                    &sender_reserved_destinations.gift_code_subaddress,
                    &mut rng,
                )
                .unwrap();

            let result =
                transaction_builder.build(&NoKeysRingSigner {}, funding_memo_builder, &mut rng);

            assert_matches!(
                result,
                Err(TxBuilderError::NewTx(NewTxError::Memo(
                    NewMemoError::MultipleOutputs
                )))
            );
        }

        // Ensure we can't write destination TxOuts for Cancellation
        {
            let cancellation_memo_builder = GiftCodeCancellationMemoBuilder::new(50);

            let mut cancellation_transaction_builder = single_input_transaction_builder(
                BlockVersion::MAX,
                token_id,
                100,
                &MockFogResolver::default(),
                &mut rng,
            );

            cancellation_transaction_builder
                .add_output(
                    Amount::new(100, token_id),
                    &sender_reserved_destinations.gift_code_subaddress,
                    &mut rng,
                )
                .unwrap();

            let cancellation_result = cancellation_transaction_builder.build(
                &NoKeysRingSigner {},
                cancellation_memo_builder,
                &mut rng,
            );

            assert_matches!(
                cancellation_result,
                Err(TxBuilderError::NewTx(NewTxError::Memo(
                    NewMemoError::DestinationMemoNotAllowed
                )))
            );
        }

        // Ensure we can't write destination TxOuts for Sending
        {
            let sender_memo_builder = GiftCodeSenderMemoBuilder::new(note).unwrap();

            let mut sending_transaction_builder = single_input_transaction_builder(
                BlockVersion::MAX,
                token_id,
                100,
                &MockFogResolver::default(),
                &mut rng,
            );

            sending_transaction_builder
                .add_output(
                    Amount::new(100, token_id),
                    &sender_reserved_destinations.gift_code_subaddress,
                    &mut rng,
                )
                .unwrap();

            let sender_result = sending_transaction_builder.build(
                &NoKeysRingSigner {},
                sender_memo_builder,
                &mut rng,
            );

            assert_matches!(
                sender_result,
                Err(TxBuilderError::NewTx(NewTxError::Memo(
                    NewMemoError::DestinationMemoNotAllowed
                )))
            );
        }
    }

    #[test]
    fn transaction_builder_defragmentation_memos() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let block_version = BlockVersion::MAX;
        let token_id = TokenId::from(62);
        let fog_resolver = MockFogResolver::default();
        let sender = AccountKey::random(&mut rng);
        let change_address = sender.change_subaddress();
        let change_destination = ReservedSubaddresses::from(&sender);

        // Adding two defrag outputs is not allowed.
        {
            let memo_builder = DefragmentationMemoBuilder::default();

            let mut transaction_builder = single_input_transaction_builder(
                block_version,
                token_id,
                100,
                &fog_resolver,
                &mut rng,
            );

            transaction_builder
                .add_output(Amount::new(100, token_id), &change_address, &mut rng)
                .unwrap();

            transaction_builder
                .add_output(Amount::new(100, token_id), &change_address, &mut rng)
                .unwrap();

            let result = transaction_builder.build(&NoKeysRingSigner {}, memo_builder, &mut rng);

            assert_matches!(
                result,
                Err(TxBuilderError::NewTx(NewTxError::Memo(
                    NewMemoError::MultipleOutputs
                )))
            );
        }

        // Adding the change output before a defrag output is not allowed.
        {
            let memo_builder = DefragmentationMemoBuilder::default();

            let mut transaction_builder = single_input_transaction_builder(
                block_version,
                token_id,
                100,
                &fog_resolver,
                &mut rng,
            );

            transaction_builder
                .add_change_output(Amount::new(0, token_id), &change_destination, &mut rng)
                .unwrap();

            let result = transaction_builder.build(&NoKeysRingSigner {}, memo_builder, &mut rng);

            assert_matches!(
                result,
                Err(TxBuilderError::NewTx(NewTxError::Memo(
                    NewMemoError::MissingOutput
                )))
            );
        }

        // Change in a different token is not allowed.
        {
            let memo_builder = DefragmentationMemoBuilder::default();

            let mut transaction_builder = single_input_transaction_builder(
                block_version,
                Mob::ID,
                100,
                &fog_resolver,
                &mut rng,
            );

            transaction_builder
                .add_output(Amount::new(100, Mob::ID), &change_address, &mut rng)
                .unwrap();

            transaction_builder
                .add_change_output(Amount::new(0, token_id), &change_destination, &mut rng)
                .unwrap();

            let result = transaction_builder.build(&NoKeysRingSigner {}, memo_builder, &mut rng);

            assert_matches!(
                result,
                Err(TxBuilderError::NewTx(NewTxError::Memo(
                    NewMemoError::MixedTokenIds
                )))
            );
        }

        // Defrag change output should always be 0
        {
            let memo_builder = DefragmentationMemoBuilder::default();

            let mut transaction_builder = single_input_transaction_builder(
                block_version,
                token_id,
                113,
                &fog_resolver,
                &mut rng,
            );

            transaction_builder
                .add_output(Amount::new(113, token_id), &change_address, &mut rng)
                .unwrap();
            transaction_builder
                .add_change_output(Amount::new(43, token_id), &change_destination, &mut rng)
                .unwrap();

            let result = transaction_builder.build(&NoKeysRingSigner {}, memo_builder, &mut rng);

            assert_matches!(
                result,
                Err(TxBuilderError::NewTx(NewTxError::Memo(
                    NewMemoError::DefragWithChange
                )))
            );
        }

        // Test builds memos with no ID
        {
            let memo_builder = DefragmentationMemoBuilder::default();
            let mut transaction_builder = single_input_transaction_builder(
                block_version,
                token_id,
                432,
                &fog_resolver,
                &mut rng,
            );
            transaction_builder.set_fee(3).unwrap();

            let TxOutContext {
                tx_out_public_key: defrag_tx_out_public_key,
                ..
            } = transaction_builder
                .add_output(Amount::new(429, token_id), &change_address, &mut rng)
                .unwrap();

            let TxOutContext {
                tx_out_public_key: decoy_tx_out_public_key,
                ..
            } = transaction_builder
                .add_change_output(Amount::new(0, token_id), &change_destination, &mut rng)
                .unwrap();

            let tx = transaction_builder
                .build(&NoKeysRingSigner {}, memo_builder, &mut rng)
                .expect("build tx");

            assert_eq!(tx.prefix.outputs.len(), 2);

            let main_output = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| tx_out.public_key == defrag_tx_out_public_key)
                .expect("Didn't find recipient's output");
            let decoy_output = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| tx_out.public_key == decoy_tx_out_public_key)
                .expect("Didn't find sender's output");

            // Defrag output should have a defrag memo
            let memo = validate_amount_and_get_memo(
                block_version,
                main_output,
                &sender,
                Amount::new(429, token_id),
            );
            let MemoType::Defragmentation(memo) = memo.unwrap() else {
                panic!("unexpected memo type")
            };
            assert_eq!(memo.defrag_id(), 0u64);
            assert_eq!(memo.fee(), 3u64);
            assert_eq!(memo.total_outlay(), 432u64);

            // Change output should have a 0 value defrag memo
            let memo = validate_amount_and_get_memo(
                block_version,
                decoy_output,
                &sender,
                Amount::new(0, token_id),
            );
            let MemoType::Defragmentation(memo) = memo.unwrap() else {
                panic!("unexpected memo type")
            };
            assert_eq!(memo.defrag_id(), 0u64);
            assert_eq!(memo.fee(), 0u64);
            assert_eq!(memo.total_outlay(), 0u64);
        }

        // Test builds memos with ID
        {
            let memo_builder = DefragmentationMemoBuilder::new(64);
            let mut transaction_builder = single_input_transaction_builder(
                block_version,
                token_id,
                432,
                &fog_resolver,
                &mut rng,
            );
            transaction_builder.set_fee(3).unwrap();

            let TxOutContext {
                tx_out_public_key: defrag_tx_out_public_key,
                ..
            } = transaction_builder
                .add_output(Amount::new(429, token_id), &change_address, &mut rng)
                .unwrap();

            let TxOutContext {
                tx_out_public_key: decoy_tx_out_public_key,
                ..
            } = transaction_builder
                .add_change_output(Amount::new(0, token_id), &change_destination, &mut rng)
                .unwrap();

            let tx = transaction_builder
                .build(&NoKeysRingSigner {}, memo_builder, &mut rng)
                .expect("build tx");

            assert_eq!(tx.prefix.outputs.len(), 2);

            let main_output = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| tx_out.public_key == defrag_tx_out_public_key)
                .expect("Didn't find recipient's output");
            let decoy_output = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| tx_out.public_key == decoy_tx_out_public_key)
                .expect("Didn't find sender's output");

            // Defrag output should have a defrag memo
            let memo = validate_amount_and_get_memo(
                block_version,
                main_output,
                &sender,
                Amount::new(429, token_id),
            );
            let MemoType::Defragmentation(memo) = memo.unwrap() else {
                panic!("unexpected memo type")
            };
            assert_eq!(memo.defrag_id(), 64u64);
            assert_eq!(memo.fee(), 3u64);
            assert_eq!(memo.total_outlay(), 432u64);

            // Change output should have a 0 value defrag memo
            let memo = validate_amount_and_get_memo(
                block_version,
                decoy_output,
                &sender,
                Amount::new(0, token_id),
            );
            let MemoType::Defragmentation(memo) = memo.unwrap() else {
                panic!("unexpected memo type")
            };
            assert_eq!(memo.defrag_id(), 64u64);
            assert_eq!(memo.fee(), 0u64);
            assert_eq!(memo.total_outlay(), 0u64);
        }
    }
}
