// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A builder object for signed contingent inputs (see MCIP #31)
//! This plays a similar role to the transaction builder.

use crate::{
    InputCredentials, MemoBuilder, ReservedSubaddresses, SignedContingentInputBuilderError,
    TxBuilderError,
};
use core::cmp::min;
use mc_account_keys::PublicAddress;
use mc_crypto_ring_signature_signer::{RingSigner, SignableInputRing};
use mc_fog_report_validation::FogPubkeyResolver;
use mc_transaction_core::{
    ring_ct::OutputSecret,
    ring_signature::Scalar,
    tx::{TxIn, TxOut, TxOutConfirmationNumber},
    Amount, BlockVersion, InputRules, MemoContext, MemoPayload, NewMemoError,
    SignedContingentInput, TokenId, UnmaskedAmount,
};
use rand_core::{CryptoRng, RngCore};

/// Helper utility for creating signed contingent inputs with required outputs,
/// and attaching fog hint and memos as appropriate.
///
/// This is generic over FogPubkeyResolver because there are several reasonable
/// implementations of that.
///
/// This is generic over MemoBuilder to allow injecting a policy for how to
/// use the memos in the TxOuts.
#[derive(Debug)]
pub struct SignedContingentInputBuilder<FPR: FogPubkeyResolver> {
    /// The block version that we are targeting for this input
    block_version: BlockVersion,
    /// The input which is being signed
    input_credentials: InputCredentials,
    /// The outputs required by the rules for this signed input, and associated
    /// secrets
    required_outputs_and_secrets: Vec<(TxOut, OutputSecret)>,
    /// The tombstone_block value, a block index in which the signed input
    /// expires, and can no longer be used. (This works by implying a limit
    /// on the tombstone block for any transaction which incorporates the signed
    /// input.)
    tombstone_block: u64,
    /// The source of validated fog pubkeys used for this signed contingent
    /// input
    fog_resolver: FPR,
    /// The limit on the tombstone block value imposed by pubkey_expiry values
    /// in fog pubkeys used so far
    fog_tombstone_block_limit: u64,
    /// A policy object implementing MemoBuilder which constructs memos for
    /// the outputs which are required by the rules.
    ///
    /// This is an Option in order to allow working around the borrow checker.
    /// Box<dyn ...> is used because having more generic parameters creates more
    /// types that SDKs must bind to if they support multiple memo builder
    /// types.
    memo_builder: Option<Box<dyn MemoBuilder + 'static + Send + Sync>>,
}

impl<FPR: FogPubkeyResolver> SignedContingentInputBuilder<FPR> {
    /// Initializes a new SignedContingentInputBuilder.
    ///
    /// # Arguments
    /// * `block_version` - The block version rules to use when signing the
    ///   input
    /// * `input_credentials` - Credentials for the input we are signing
    /// * `tx_out_global_indices` - Global indices for the tx out's in the ring
    /// * `fog_resolver` - Source of validated fog keys to use with outputs for
    ///   this signed contingent input
    /// * `memo_builder` - An object which creates memos for the TxOuts in this
    ///   signed contingent input
    pub fn new<MB: MemoBuilder + 'static + Send + Sync>(
        block_version: BlockVersion,
        input_credentials: InputCredentials,
        fog_resolver: FPR,
        memo_builder: MB,
    ) -> Result<Self, SignedContingentInputBuilderError> {
        Self::new_with_box(
            block_version,
            input_credentials,
            fog_resolver,
            Box::new(memo_builder),
        )
    }

    /// Initializes a new SignedContingentInputBuilder, using a Box<dyn
    /// MemoBuilder> instead of statically typed
    ///
    /// # Arguments
    /// * `block_version` - The block version to use when signing the input
    /// * `input_credentials` - Credentials for the input we are signing
    /// * `tx_out_global_indices` - Global indices for the tx out's in the ring
    /// * `fog_resolver` - Source of validated fog keys to use with outputs for
    ///   this signed contingent input
    /// * `memo_builder` - An object which creates memos for the TxOuts in this
    ///   signed contingent input
    pub fn new_with_box(
        block_version: BlockVersion,
        input_credentials: InputCredentials,
        fog_resolver: FPR,
        mut memo_builder: Box<dyn MemoBuilder + Send + Sync>,
    ) -> Result<Self, SignedContingentInputBuilderError> {
        if input_credentials.ring.len() != input_credentials.membership_proofs.len() {
            return Err(SignedContingentInputBuilderError::MissingProofs(
                input_credentials.ring.len(),
                input_credentials.membership_proofs.len(),
            ));
        }
        // The fee is paid by the party using the transaction builder, not the
        // party using the signed contingent input. So we say 0 for purpose of memos
        // here, which go on change outputs for the party using this builder.
        memo_builder.set_fee(Amount::new(0, TokenId::from(0)))?;
        Ok(Self {
            block_version,
            input_credentials,
            required_outputs_and_secrets: Vec::new(),
            tombstone_block: u64::max_value(),
            fog_resolver,
            fog_tombstone_block_limit: u64::max_value(),
            memo_builder: Some(memo_builder),
        })
    }

    /// Add a non-change required output to the input rules.
    ///
    /// If a sender memo credential has been set, this will create an
    /// authenticated sender memo for the TxOut. Otherwise the memo will be
    /// unused.
    ///
    /// # Arguments
    /// * `amount` - The amount of this output
    /// * `recipient` - The recipient's public address
    /// * `rng` - RNG used to generate blinding for commitment
    pub fn add_required_output<RNG: CryptoRng + RngCore>(
        &mut self,
        amount: Amount,
        recipient: &PublicAddress,
        rng: &mut RNG,
    ) -> Result<(TxOut, TxOutConfirmationNumber), TxBuilderError> {
        // Taking self.memo_builder here means that we can call functions on &mut self,
        // and pass them something that has captured the memo builder.
        // Calling take() on Option<Box> is just moving a pointer.
        let mut mb = self
            .memo_builder
            .take()
            .expect("memo builder is missing, this is a logic error");
        let result = self.add_required_output_with_fog_hint_address(
            amount,
            recipient,
            recipient,
            |memo_ctxt| mb.make_memo_for_output(amount, recipient, memo_ctxt),
            rng,
        );
        // Put the memo builder back
        self.memo_builder = Some(mb);
        result
    }

    /// Add a standard change required output to the input rules.
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
    /// # Arguments
    /// * `amount` - The amount of this change output.
    /// * `change_destination` - An object including both a primary address and
    ///   a change subaddress to use to create this change output. The primary
    ///   address is used for the fog hint, the change subaddress owns the
    ///   change output. These can both be obtained from an account key, but
    ///   this API does not require the account key.
    /// * `rng` - RNG used to generate blinding for commitment
    pub fn add_required_change_output<RNG: CryptoRng + RngCore>(
        &mut self,
        amount: Amount,
        change_destination: &ReservedSubaddresses,
        rng: &mut RNG,
    ) -> Result<(TxOut, TxOutConfirmationNumber), TxBuilderError> {
        // Taking self.memo_builder here means that we can call functions on &mut self,
        // and pass them something that has captured the memo builder.
        // Calling take() on Option<Box> is just moving a pointer.
        let mut mb = self
            .memo_builder
            .take()
            .expect("memo builder is missing, this is a logic error");
        let result = self.add_required_output_with_fog_hint_address(
            amount,
            &change_destination.change_subaddress,
            &change_destination.primary_address,
            |memo_ctxt| mb.make_memo_for_change_output(amount, change_destination, memo_ctxt),
            rng,
        );
        // Put the memo builder back
        self.memo_builder = Some(mb);
        result
    }

    /// Add a required output to the rules, using `fog_hint_address` to
    /// construct the fog hint.
    ///
    /// This is a private implementation detail, and generally, fog users expect
    /// that the transactions that they receive from fog belong to the account
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
    /// * `memo_fn` - The memo function to use (see TxOut::new_with_memo)
    /// * `rng` - RNG used to generate blinding for commitment
    fn add_required_output_with_fog_hint_address<RNG: CryptoRng + RngCore>(
        &mut self,
        amount: Amount,
        recipient: &PublicAddress,
        fog_hint_address: &PublicAddress,
        memo_fn: impl FnOnce(MemoContext) -> Result<MemoPayload, NewMemoError>,
        rng: &mut RNG,
    ) -> Result<(TxOut, TxOutConfirmationNumber), TxBuilderError> {
        let (hint, pubkey_expiry) =
            crate::transaction_builder::create_fog_hint(fog_hint_address, &self.fog_resolver, rng)?;

        let (tx_out, shared_secret) = crate::transaction_builder::create_output_with_fog_hint(
            self.block_version,
            amount,
            recipient,
            hint,
            memo_fn,
            rng,
        )?;

        let (amount, blinding) = tx_out
            .get_masked_amount()
            .expect("SignedContingentInputBuilder created an invalid MaskedAmount")
            .get_value(&shared_secret)
            .expect("SignedContingentInputBuilder created an invalid Amount");
        let output_secret = OutputSecret { amount, blinding };

        self.impose_tombstone_block_limit(pubkey_expiry);

        self.required_outputs_and_secrets
            .push((tx_out.clone(), output_secret));

        let confirmation = TxOutConfirmationNumber::from(&shared_secret);

        Ok((tx_out, confirmation))
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

    /// Consume the builder and return the transaction.
    pub fn build<RNG: CryptoRng + RngCore>(
        mut self,
        ring_signer: &impl RingSigner,
        rng: &mut RNG,
    ) -> Result<SignedContingentInput, TxBuilderError> {
        if !self.block_version.signed_input_rules_are_supported()
            || !self.block_version.mixed_transactions_are_supported()
        {
            return Err(TxBuilderError::BlockVersionTooOld(
                *self.block_version,
                *BlockVersion::THREE,
            ));
        }

        if self.block_version > BlockVersion::MAX {
            return Err(TxBuilderError::BlockVersionTooNew(
                *self.block_version,
                *BlockVersion::MAX,
            ));
        }

        self.required_outputs_and_secrets
            .sort_by(|(a, _), (b, _)| a.public_key.cmp(&b.public_key));

        let (outputs, output_secrets): (Vec<TxOut>, Vec<_>) =
            self.required_outputs_and_secrets.drain(..).unzip();

        let input_rules = InputRules {
            required_outputs: outputs,
            max_tombstone_block: if self.tombstone_block == u64::max_value() {
                0
            } else {
                self.tombstone_block
            },
            fractional_outputs: Default::default(),
            fractional_change: None,
            max_allowed_change_value: 0,
        };

        // Get the tx out indices from the proofs in the input credentials,
        // after sorting has happened
        let tx_out_global_indices: Vec<u64> = self
            .input_credentials
            .membership_proofs
            .iter()
            .map(|proof| proof.index)
            .collect();

        // Now we can create the mlsag
        let mut tx_in = TxIn::from(&self.input_credentials);
        tx_in.input_rules = Some(input_rules);
        // Clear the merkle proofs, because this makes the SCI smaller,
        // and the recipient needs to regenerate them later most likely anyways.
        tx_in.proofs.clear();
        let ring = SignableInputRing::try_from(self.input_credentials)?;

        let pseudo_output_blinding = Scalar::random(rng);

        let mlsag = ring_signer.sign(
            &tx_in
                .signed_digest()
                .expect("Tx in should contain rules, this is a logic error"),
            &ring,
            pseudo_output_blinding,
            rng,
        )?;

        let pseudo_output_amount = UnmaskedAmount {
            value: ring.input_secret.amount.value,
            token_id: *ring.input_secret.amount.token_id,
            blinding: pseudo_output_blinding.into(),
        };

        let required_output_amounts: Vec<UnmaskedAmount> =
            output_secrets.into_iter().map(Into::into).collect();

        Ok(SignedContingentInput {
            block_version: *self.block_version,
            tx_in,
            mlsag,
            pseudo_output_amount,
            required_output_amounts,
            tx_out_global_indices,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        test_utils::get_input_credentials, EmptyMemoBuilder, MemoType, TransactionBuilder,
    };
    use assert_matches::assert_matches;
    use maplit::btreemap;
    use mc_account_keys::{AccountKey, CHANGE_SUBADDRESS_INDEX, DEFAULT_SUBADDRESS_INDEX};
    use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
    use mc_crypto_ring_signature_signer::NoKeysRingSigner;
    use mc_fog_report_validation_test_utils::{FullyValidatedFogPubkey, MockFogResolver};
    use mc_transaction_core::{
        constants::MILLIMOB_TO_PICOMOB,
        fog_hint::FogHint,
        get_tx_out_shared_secret,
        ring_ct::Error as RingCtError,
        ring_signature::KeyImage,
        subaddress_matches_tx_out,
        tokens::Mob,
        validation::{
            validate_all_input_rules, validate_inputs_are_sorted, validate_outputs_are_sorted,
            validate_ring_elements_are_sorted, validate_signature, validate_tx_out,
            TransactionValidationError,
        },
        Amount, InputRuleError, SignedContingentInputError, Token, TokenId,
    };
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    // Test a signed contingent input with a fog recipient
    fn test_simple_fog_signed_contingent_input() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for block_version in 3..=*BlockVersion::MAX {
            let block_version = BlockVersion::try_from(block_version).unwrap();

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
            let amount = Amount::new(value, Mob::ID);
            let amount2 = Amount::new(100_000, 2.into());

            let input_credentials =
                get_input_credentials(block_version, amount, &sender, &fog_resolver, &mut rng);

            let key_image = KeyImage::from(input_credentials.assert_has_onetime_private_key());

            let mut builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                fog_resolver,
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            let (_txout, confirmation) = builder
                .add_required_output(amount2, &recipient.default_subaddress(), &mut rng)
                .unwrap();

            builder.set_tombstone_block(2000);

            let sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // The contingent input should have a valid signature.
            sci.validate().unwrap();

            // The contingent input should have the correct key image.
            assert_eq!(sci.key_image(), key_image);

            // The contingent input rules should respect fog pubkey expiry limit
            assert_eq!(
                sci.tx_in.input_rules.as_ref().unwrap().max_tombstone_block,
                1000
            );

            // The contingent input should have one output.
            assert_eq!(
                sci.tx_in
                    .input_rules
                    .as_ref()
                    .unwrap()
                    .required_outputs
                    .len(),
                1
            );

            let output = sci.tx_in.input_rules.as_ref().unwrap().required_outputs[0].clone();

            validate_tx_out(block_version, &output).unwrap();

            // The output should belong to the correct recipient.
            assert!(
                subaddress_matches_tx_out(&recipient, DEFAULT_SUBADDRESS_INDEX, &output).unwrap()
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
        }
    }

    #[test]
    // Test a signed contingent input with two fog recipients
    fn test_two_fogs_signed_contingent_input() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for block_version in 3..=*BlockVersion::MAX {
            let block_version = BlockVersion::try_from(block_version).unwrap();

            let sender = AccountKey::new_with_fog(
                &FromRandom::from_random(&mut rng),
                &FromRandom::from_random(&mut rng),
                "fog://demo.com".to_string(),
                Default::default(),
                vec![],
            );
            let recipient = AccountKey::random_with_fog(&mut rng);
            let ingest_private_key1 = RistrettoPrivate::from_random(&mut rng);
            let ingest_private_key2 = RistrettoPrivate::from_random(&mut rng);

            let fog_resolver = MockFogResolver(btreemap! {
                                sender
                        .default_subaddress()
                        .fog_report_url()
                        .unwrap()
                        .to_string()
                =>
                    FullyValidatedFogPubkey {
                        pubkey: RistrettoPublic::from(&ingest_private_key1),
                        pubkey_expiry: 1000,
                    },
                                recipient
                        .default_subaddress()
                        .fog_report_url()
                        .unwrap()
                        .to_string()
                =>
                    FullyValidatedFogPubkey {
                        pubkey: RistrettoPublic::from(&ingest_private_key2),
                        pubkey_expiry: 1500,
                    },
            });

            let value = 1475 * MILLIMOB_TO_PICOMOB;
            let amount = Amount::new(value, Mob::ID);
            let amount2 = Amount::new(100_000, 2.into());

            let input_credentials =
                get_input_credentials(block_version, amount, &sender, &fog_resolver, &mut rng);

            let key_image = KeyImage::from(input_credentials.assert_has_onetime_private_key());

            let mut builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                fog_resolver,
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            let (_txout, confirmation) = builder
                .add_required_output(amount2, &recipient.default_subaddress(), &mut rng)
                .unwrap();

            builder.set_tombstone_block(2000);

            let sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // The contingent input should have a valid signature.
            sci.validate().unwrap();

            // The contingent input should have the correct key image.
            assert_eq!(sci.key_image(), key_image);

            // The contingent input rules should respect fog pubkey expiry limit,
            // choosing the recipient's fog pubkey expiry
            assert_eq!(
                sci.tx_in.input_rules.as_ref().unwrap().max_tombstone_block,
                1500
            );

            // The contingent input should have one output.
            assert_eq!(
                sci.tx_in
                    .input_rules
                    .as_ref()
                    .unwrap()
                    .required_outputs
                    .len(),
                1
            );

            let output = sci.tx_in.input_rules.as_ref().unwrap().required_outputs[0].clone();

            validate_tx_out(block_version, &output).unwrap();

            // The output should belong to the correct recipient.
            assert!(
                subaddress_matches_tx_out(&recipient, DEFAULT_SUBADDRESS_INDEX, &output).unwrap()
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
                    &ingest_private_key2,
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
        }
    }

    #[test]
    // Test that a signed contingent input with a fog recipient is spendable by Tx
    // builder
    fn test_fog_contingent_input_spendable_no_memos() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for block_version in 3..=*BlockVersion::MAX {
            let block_version = BlockVersion::try_from(block_version).unwrap();

            let alice = AccountKey::random(&mut rng);
            let bob = AccountKey::random_with_fog(&mut rng);
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);

            let fog_resolver = MockFogResolver(btreemap! {
                                bob
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
            let amount = Amount::new(value, Mob::ID);
            let token2 = TokenId::from(2);
            let amount2 = Amount::new(100_000, token2);

            // Alice provides amount of Mob
            let input_credentials =
                get_input_credentials(block_version, amount, &alice, &fog_resolver, &mut rng);

            let proofs = input_credentials.membership_proofs.clone();
            let key_image = KeyImage::from(input_credentials.assert_has_onetime_private_key());

            let mut builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Alice requests amount2 worth of token id 2 in exchange
            let (_txout, _confirmation) = builder
                .add_required_output(amount2, &alice.default_subaddress(), &mut rng)
                .unwrap();

            let mut sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // The contingent input should have a valid signature.
            sci.validate().unwrap();

            // The contingent input should have the expected key image
            assert_eq!(sci.key_image(), key_image);

            // Bob has 3x worth of token id 2
            let input_credentials = get_input_credentials(
                block_version,
                Amount::new(300_000, token2),
                &bob,
                &fog_resolver,
                &mut rng,
            );

            let mut builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, Mob::ID),
                fog_resolver,
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Bob supplies his (excess) token id 2
            builder.add_input(input_credentials);

            // Bob adds the presigned input, which also adds the required outputs
            sci.tx_in.proofs = proofs;
            builder.add_presigned_input(sci).unwrap();

            let bob_change_dest = ReservedSubaddresses::from(&bob);

            // Bob keeps the change from token id 2
            builder
                .add_change_output(Amount::new(200_000, token2), &bob_change_dest, &mut rng)
                .unwrap();

            // Bob keeps the Mob that Alice supplies, less fees
            builder
                .add_output(
                    Amount::new(value - Mob::MINIMUM_FEE, Mob::ID),
                    &bob.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            let tx = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // tx should have a valid signature, and pass all input rule checks
            validate_signature(block_version, &tx, &mut rng).unwrap();
            validate_all_input_rules(block_version, &tx).unwrap();

            // tx inputs and outputs should be sorted
            validate_inputs_are_sorted(&tx.prefix).unwrap();
            validate_ring_elements_are_sorted(&tx.prefix).unwrap();
            validate_outputs_are_sorted(&tx.prefix).unwrap();

            // The transaction should have two inputs.
            assert_eq!(tx.prefix.inputs.len(), 2);

            // The transaction should have three outputs.
            assert_eq!(tx.prefix.outputs.len(), 3);

            // The tombstone block should be the min of what the user requested, and what
            // fog limits it to
            assert_eq!(tx.prefix.tombstone_block, 1000);

            let bob_output = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| {
                    subaddress_matches_tx_out(&bob, DEFAULT_SUBADDRESS_INDEX, tx_out).unwrap()
                })
                .expect("Didn't find bob's MOB output");

            let bob_change = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| {
                    subaddress_matches_tx_out(&bob, CHANGE_SUBADDRESS_INDEX, tx_out).unwrap()
                })
                .expect("Didn't find bob's T2 output");

            let alice_output = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| {
                    subaddress_matches_tx_out(&alice, DEFAULT_SUBADDRESS_INDEX, tx_out).unwrap()
                })
                .expect("Didn't find alice's output");

            validate_tx_out(block_version, bob_output).unwrap();
            validate_tx_out(block_version, bob_change).unwrap();
            validate_tx_out(block_version, alice_output).unwrap();

            // Bob's MOB output should belong to the correct recipient and have correct
            // amount and have correct memo
            {
                let ss = get_tx_out_shared_secret(
                    bob.view_private_key(),
                    &RistrettoPublic::try_from(&bob_output.public_key).unwrap(),
                );
                let (amount, _) = bob_output
                    .get_masked_amount()
                    .unwrap()
                    .get_value(&ss)
                    .unwrap();
                assert_eq!(amount, Amount::new(value - Mob::MINIMUM_FEE, Mob::ID));

                let memo = bob_output.e_memo.unwrap().decrypt(&ss);
                assert_matches!(
                    MemoType::try_from(&memo).expect("Couldn't decrypt memo"),
                    MemoType::Unused(_)
                );
            }

            // Bob's T2 change should belong to the correct recipient and have correct
            // amount and have correct memo
            {
                let ss = get_tx_out_shared_secret(
                    bob.view_private_key(),
                    &RistrettoPublic::try_from(&bob_change.public_key).unwrap(),
                );
                let (amount, _) = bob_change
                    .get_masked_amount()
                    .unwrap()
                    .get_value(&ss)
                    .unwrap();
                assert_eq!(amount, Amount::new(200_000, token2));

                let memo = bob_change.e_memo.unwrap().decrypt(&ss);
                assert_matches!(
                    MemoType::try_from(&memo).expect("Couldn't decrypt memo"),
                    MemoType::Unused(_)
                );
            }

            // Alice's T2 output should belong to the correct recipient and have correct
            // amount and have correct memo
            {
                let ss = get_tx_out_shared_secret(
                    alice.view_private_key(),
                    &RistrettoPublic::try_from(&alice_output.public_key).unwrap(),
                );
                let (amount, _) = alice_output
                    .get_masked_amount()
                    .unwrap()
                    .get_value(&ss)
                    .unwrap();
                assert_eq!(amount, amount2);

                let memo = alice_output.e_memo.unwrap().decrypt(&ss);
                assert_matches!(
                    MemoType::try_from(&memo).expect("Couldn't decrypt memo"),
                    MemoType::Unused(_)
                );
            }

            // Bob's Mob output fog hint should contain the correct public key.
            {
                let mut output_fog_hint = FogHint::new(RistrettoPublic::from_random(&mut rng));
                assert!(bool::from(FogHint::ct_decrypt(
                    &ingest_private_key,
                    &bob_output.e_fog_hint,
                    &mut output_fog_hint,
                )));
                assert_eq!(
                    output_fog_hint.get_view_pubkey(),
                    &CompressedRistrettoPublic::from(bob.default_subaddress().view_public_key())
                );
            }

            // Bob's change output fog hint should contain the correct public key.
            {
                let mut output_fog_hint = FogHint::new(RistrettoPublic::from_random(&mut rng));
                assert!(bool::from(FogHint::ct_decrypt(
                    &ingest_private_key,
                    &bob_change.e_fog_hint,
                    &mut output_fog_hint,
                )));
                assert_eq!(
                    output_fog_hint.get_view_pubkey(),
                    &CompressedRistrettoPublic::from(bob.default_subaddress().view_public_key())
                );
            }
        }
    }

    #[test]
    // Test that a signed contingent input with fog recipient is spendable by Tx
    // builder, by another fog user
    fn test_two_fogs_contingent_input_spendable_no_memos() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for block_version in 3..=*BlockVersion::MAX {
            let block_version = BlockVersion::try_from(block_version).unwrap();

            let alice = AccountKey::new_with_fog(
                &FromRandom::from_random(&mut rng),
                &FromRandom::from_random(&mut rng),
                "fog://alice.com".to_string(),
                Default::default(),
                vec![],
            );
            let bob = AccountKey::random_with_fog(&mut rng);
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);

            let fog_resolver = MockFogResolver(btreemap! {
                                alice
                        .default_subaddress()
                        .fog_report_url()
                        .unwrap()
                        .to_string()
                =>
                    FullyValidatedFogPubkey {
                        pubkey: RistrettoPublic::from(&ingest_private_key),
                        pubkey_expiry: 1000,
                    },
                                bob
                        .default_subaddress()
                        .fog_report_url()
                        .unwrap()
                        .to_string()
                =>
                    FullyValidatedFogPubkey {
                        pubkey: RistrettoPublic::from(&ingest_private_key),
                        pubkey_expiry: 1500,
                    },
            });

            let value = 1475 * MILLIMOB_TO_PICOMOB;
            let amount = Amount::new(value, Mob::ID);
            let token2 = TokenId::from(2);
            let amount2 = Amount::new(100_000, token2);

            // Alice provides amount of Mob
            let input_credentials =
                get_input_credentials(block_version, amount, &alice, &fog_resolver, &mut rng);

            let proofs = input_credentials.membership_proofs.clone();
            let key_image = KeyImage::from(input_credentials.assert_has_onetime_private_key());

            let mut builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Alice requests amount2 worth of token id 2 in exchange
            let (_txout, _confirmation) = builder
                .add_required_output(amount2, &alice.default_subaddress(), &mut rng)
                .unwrap();

            let mut sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // The contingent input should have a valid signature.
            sci.validate().unwrap();

            // The contingent input should have the expected key image
            assert_eq!(sci.key_image(), key_image);

            // Bob has 3x worth of token id 2
            let input_credentials = get_input_credentials(
                block_version,
                Amount::new(300_000, token2),
                &bob,
                &fog_resolver,
                &mut rng,
            );

            let mut builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, Mob::ID),
                fog_resolver,
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Bob supplies his (excess) token id 2
            builder.add_input(input_credentials);

            // Bob adds the presigned input, which also adds the required outputs
            sci.tx_in.proofs = proofs;
            builder.add_presigned_input(sci).unwrap();

            let bob_change_dest = ReservedSubaddresses::from(&bob);

            // Bob keeps the change from token id 2
            builder
                .add_change_output(Amount::new(200_000, token2), &bob_change_dest, &mut rng)
                .unwrap();

            // Bob keeps the Mob that Alice supplies, less fees
            builder
                .add_output(
                    Amount::new(value - Mob::MINIMUM_FEE, Mob::ID),
                    &bob.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            let tx = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // tx should have a valid signature, and pass all input rule checks
            validate_signature(block_version, &tx, &mut rng).unwrap();
            validate_all_input_rules(block_version, &tx).unwrap();

            // tx inputs and outputs should be sorted
            validate_inputs_are_sorted(&tx.prefix).unwrap();
            validate_ring_elements_are_sorted(&tx.prefix).unwrap();
            validate_outputs_are_sorted(&tx.prefix).unwrap();

            // The transaction should have two inputs.
            assert_eq!(tx.prefix.inputs.len(), 2);

            // The transaction should have three outputs.
            assert_eq!(tx.prefix.outputs.len(), 3);

            // The tombstone block should be the min of what the user requested, and what
            // fog limits it to, for both fogs
            assert_eq!(tx.prefix.tombstone_block, 1000);

            let bob_output = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| {
                    subaddress_matches_tx_out(&bob, DEFAULT_SUBADDRESS_INDEX, tx_out).unwrap()
                })
                .expect("Didn't find bob's MOB output");

            let bob_change = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| {
                    subaddress_matches_tx_out(&bob, CHANGE_SUBADDRESS_INDEX, tx_out).unwrap()
                })
                .expect("Didn't find bob's T2 output");

            let alice_output = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| {
                    subaddress_matches_tx_out(&alice, DEFAULT_SUBADDRESS_INDEX, tx_out).unwrap()
                })
                .expect("Didn't find alice's output");

            validate_tx_out(block_version, bob_output).unwrap();
            validate_tx_out(block_version, bob_change).unwrap();
            validate_tx_out(block_version, alice_output).unwrap();

            // Bob's MOB output should belong to the correct recipient and have correct
            // amount and have correct memo
            {
                let ss = get_tx_out_shared_secret(
                    bob.view_private_key(),
                    &RistrettoPublic::try_from(&bob_output.public_key).unwrap(),
                );
                let (amount, _) = bob_output
                    .get_masked_amount()
                    .unwrap()
                    .get_value(&ss)
                    .unwrap();
                assert_eq!(amount, Amount::new(value - Mob::MINIMUM_FEE, Mob::ID));

                let memo = bob_output.e_memo.unwrap().decrypt(&ss);
                assert_matches!(
                    MemoType::try_from(&memo).expect("Couldn't decrypt memo"),
                    MemoType::Unused(_)
                );
            }

            // Bob's T2 change should belong to the correct recipient and have correct
            // amount and have correct memo
            {
                let ss = get_tx_out_shared_secret(
                    bob.view_private_key(),
                    &RistrettoPublic::try_from(&bob_change.public_key).unwrap(),
                );
                let (amount, _) = bob_change
                    .get_masked_amount()
                    .unwrap()
                    .get_value(&ss)
                    .unwrap();
                assert_eq!(amount, Amount::new(200_000, token2));

                let memo = bob_change.e_memo.unwrap().decrypt(&ss);
                assert_matches!(
                    MemoType::try_from(&memo).expect("Couldn't decrypt memo"),
                    MemoType::Unused(_)
                );
            }

            // Alice's T2 output should belong to the correct recipient and have correct
            // amount and have correct memo
            {
                let ss = get_tx_out_shared_secret(
                    alice.view_private_key(),
                    &RistrettoPublic::try_from(&alice_output.public_key).unwrap(),
                );
                let (amount, _) = alice_output
                    .get_masked_amount()
                    .unwrap()
                    .get_value(&ss)
                    .unwrap();
                assert_eq!(amount, amount2);

                let memo = alice_output.e_memo.unwrap().decrypt(&ss);
                assert_matches!(
                    MemoType::try_from(&memo).expect("Couldn't decrypt memo"),
                    MemoType::Unused(_)
                );
            }

            // Bob's Mob output fog hint should contain the correct public key.
            {
                let mut output_fog_hint = FogHint::new(RistrettoPublic::from_random(&mut rng));
                assert!(bool::from(FogHint::ct_decrypt(
                    &ingest_private_key,
                    &bob_output.e_fog_hint,
                    &mut output_fog_hint,
                )));
                assert_eq!(
                    output_fog_hint.get_view_pubkey(),
                    &CompressedRistrettoPublic::from(bob.default_subaddress().view_public_key())
                );
            }

            // Bob's change output fog hint should contain the correct public key.
            {
                let mut output_fog_hint = FogHint::new(RistrettoPublic::from_random(&mut rng));
                assert!(bool::from(FogHint::ct_decrypt(
                    &ingest_private_key,
                    &bob_change.e_fog_hint,
                    &mut output_fog_hint,
                )));
                assert_eq!(
                    output_fog_hint.get_view_pubkey(),
                    &CompressedRistrettoPublic::from(bob.default_subaddress().view_public_key())
                );
            }
        }
    }

    #[test]
    // Test that two signed contingent inputs can be added to a single Tx and spent
    fn test_two_contingent_inputs_spendable_no_memos() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for block_version in 3..=*BlockVersion::MAX {
            let block_version = BlockVersion::try_from(block_version).unwrap();

            let alice = AccountKey::random(&mut rng);
            let bob = AccountKey::random(&mut rng);
            let charlie = AccountKey::random(&mut rng);

            let fog_resolver = MockFogResolver(Default::default());

            let value = 1475 * MILLIMOB_TO_PICOMOB;
            let amount = Amount::new(value, Mob::ID);
            let token2 = TokenId::from(2);
            let token3 = TokenId::from(3);

            // Alice provides amount of Mob
            let input_credentials =
                get_input_credentials(block_version, amount, &alice, &fog_resolver, &mut rng);

            let proofs = input_credentials.membership_proofs.clone();

            let mut builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Alice requests 100_000 token2 in exchange
            let (_txout, _confirmation) = builder
                .add_required_output(
                    Amount::new(100_000, token2),
                    &alice.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            let mut sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // The contingent input should have a valid signature.
            sci.validate().unwrap();

            // Bob has 300_000 worth of token id 2, happens to offer 100,000 of it for 666
            // token 3
            let input_credentials = get_input_credentials(
                block_version,
                Amount::new(300_000, token2),
                &bob,
                &fog_resolver,
                &mut rng,
            );

            let proofs2 = input_credentials.membership_proofs.clone();

            let mut builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Bob keeps the change from token id 2
            let bob_change_dest = ReservedSubaddresses::from(&bob);
            builder
                .add_required_change_output(
                    Amount::new(200_000, token2),
                    &bob_change_dest,
                    &mut rng,
                )
                .unwrap();

            // Bob wants 666 of token id 3
            builder
                .add_required_output(
                    Amount::new(666, token3),
                    &bob.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            let mut sci2 = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // The contingent input should have a valid signature.
            sci2.validate().unwrap();

            // Charlie wants to fill both orders
            let mut builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, Mob::ID),
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Charlie add proofs, then adds the orders
            sci.tx_in.proofs = proofs;
            sci2.tx_in.proofs = proofs2;
            builder.add_presigned_input(sci).unwrap();
            builder.add_presigned_input(sci2).unwrap();

            // Charlie supplies 999 token id 3
            builder.add_input(get_input_credentials(
                block_version,
                Amount::new(999, token3),
                &charlie,
                &fog_resolver,
                &mut rng,
            ));

            // Charlie keeps 333 as change, leaving 666 for Bob
            let charlie_change_dest = ReservedSubaddresses::from(&charlie);
            builder
                .add_change_output(Amount::new(333, token3), &charlie_change_dest, &mut rng)
                .unwrap();

            // Charlie keeps the Mob that Alice supplies, less fees
            builder
                .add_output(
                    Amount::new(value - Mob::MINIMUM_FEE, Mob::ID),
                    &charlie.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            builder.set_tombstone_block(8088);

            let tx = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // tx should have a valid signature, and pass all input rule checks
            validate_signature(block_version, &tx, &mut rng).unwrap();
            validate_all_input_rules(block_version, &tx).unwrap();

            // tx inputs and outputs should be sorted
            validate_inputs_are_sorted(&tx.prefix).unwrap();
            validate_ring_elements_are_sorted(&tx.prefix).unwrap();
            validate_outputs_are_sorted(&tx.prefix).unwrap();

            // The transaction should have two inputs.
            assert_eq!(tx.prefix.inputs.len(), 3);

            // The transaction should have five outputs.
            assert_eq!(tx.prefix.outputs.len(), 5);

            // The tombstone block should be what it was configured to
            assert_eq!(tx.prefix.tombstone_block, 8088);

            let bob_output = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| {
                    subaddress_matches_tx_out(&bob, DEFAULT_SUBADDRESS_INDEX, tx_out).unwrap()
                })
                .expect("Didn't find bob's T3 output");

            let bob_change = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| {
                    subaddress_matches_tx_out(&bob, CHANGE_SUBADDRESS_INDEX, tx_out).unwrap()
                })
                .expect("Didn't find bob's T2 output");

            let charlie_output = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| {
                    subaddress_matches_tx_out(&charlie, DEFAULT_SUBADDRESS_INDEX, tx_out).unwrap()
                })
                .expect("Didn't find charlie's MOB output");

            let charlie_change = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| {
                    subaddress_matches_tx_out(&charlie, CHANGE_SUBADDRESS_INDEX, tx_out).unwrap()
                })
                .expect("Didn't find charlie's T3 output");

            let alice_output = tx
                .prefix
                .outputs
                .iter()
                .find(|tx_out| {
                    subaddress_matches_tx_out(&alice, DEFAULT_SUBADDRESS_INDEX, tx_out).unwrap()
                })
                .expect("Didn't find alice's output");

            validate_tx_out(block_version, bob_output).unwrap();
            validate_tx_out(block_version, bob_change).unwrap();
            validate_tx_out(block_version, charlie_output).unwrap();
            validate_tx_out(block_version, charlie_change).unwrap();
            validate_tx_out(block_version, alice_output).unwrap();

            // Bob's T3 output should belong to the correct recipient and have correct
            // amount and have correct memo
            {
                let ss = get_tx_out_shared_secret(
                    bob.view_private_key(),
                    &RistrettoPublic::try_from(&bob_output.public_key).unwrap(),
                );
                let (amount, _) = bob_output
                    .get_masked_amount()
                    .unwrap()
                    .get_value(&ss)
                    .unwrap();
                assert_eq!(amount, Amount::new(666, token3));

                let memo = bob_output.e_memo.unwrap().decrypt(&ss);
                assert_matches!(
                    MemoType::try_from(&memo).expect("Couldn't decrypt memo"),
                    MemoType::Unused(_)
                );
            }

            // Bob's T2 change should belong to the correct recipient and have correct
            // amount and have correct memo
            {
                let ss = get_tx_out_shared_secret(
                    bob.view_private_key(),
                    &RistrettoPublic::try_from(&bob_change.public_key).unwrap(),
                );
                let (amount, _) = bob_change
                    .get_masked_amount()
                    .unwrap()
                    .get_value(&ss)
                    .unwrap();
                assert_eq!(amount, Amount::new(200_000, token2));

                let memo = bob_change.e_memo.unwrap().decrypt(&ss);
                assert_matches!(
                    MemoType::try_from(&memo).expect("Couldn't decrypt memo"),
                    MemoType::Unused(_)
                );
            }

            // Charlie's MOB output should belong to the correct recipient and have correct
            // amount and have correct memo
            {
                let ss = get_tx_out_shared_secret(
                    charlie.view_private_key(),
                    &RistrettoPublic::try_from(&charlie_output.public_key).unwrap(),
                );
                let (amount, _) = charlie_output
                    .get_masked_amount()
                    .unwrap()
                    .get_value(&ss)
                    .unwrap();
                assert_eq!(amount, Amount::new(value - Mob::MINIMUM_FEE, Mob::ID));

                let memo = charlie_output.e_memo.unwrap().decrypt(&ss);
                assert_matches!(
                    MemoType::try_from(&memo).expect("Couldn't decrypt memo"),
                    MemoType::Unused(_)
                );
            }

            // Charlie's T3 change should belong to the correct recipient and have correct
            // amount and have correct memo
            {
                let ss = get_tx_out_shared_secret(
                    charlie.view_private_key(),
                    &RistrettoPublic::try_from(&charlie_change.public_key).unwrap(),
                );
                let (amount, _) = charlie_change
                    .get_masked_amount()
                    .unwrap()
                    .get_value(&ss)
                    .unwrap();
                assert_eq!(amount, Amount::new(333, token3));

                let memo = charlie_change.e_memo.unwrap().decrypt(&ss);
                assert_matches!(
                    MemoType::try_from(&memo).expect("Couldn't decrypt memo"),
                    MemoType::Unused(_)
                );
            }

            // Alice's T2 output should belong to the correct recipient and have correct
            // amount and have correct memo
            {
                let ss = get_tx_out_shared_secret(
                    alice.view_private_key(),
                    &RistrettoPublic::try_from(&alice_output.public_key).unwrap(),
                );
                let (amount, _) = alice_output
                    .get_masked_amount()
                    .unwrap()
                    .get_value(&ss)
                    .unwrap();
                assert_eq!(amount, Amount::new(100_000, token2));

                let memo = alice_output.e_memo.unwrap().decrypt(&ss);
                assert_matches!(
                    MemoType::try_from(&memo).expect("Couldn't decrypt memo"),
                    MemoType::Unused(_)
                );
            }
        }
    }

    #[test]
    // Test that if you add a signed contingent input, but don't add any of your own
    // input credentials, it fails with "AllRingsPresigned".
    // (This is expected because (1) there would be no reason for someone to make
    // signed inputs like this, and (2) there needs to be at least one
    // pseudo-output where the transaction builder can choose a blinding factor
    // for it.)
    fn test_contingent_input_rules_no_input_credentials_doesnt_work() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for block_version in 3..=*BlockVersion::MAX {
            let block_version = BlockVersion::try_from(block_version).unwrap();

            let alice = AccountKey::random(&mut rng);
            let bob = AccountKey::random_with_fog(&mut rng);
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);

            let fog_resolver = MockFogResolver(btreemap! {
                                bob
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
            let amount = Amount::new(value, Mob::ID);
            let token2 = TokenId::from(2);
            let amount2 = Amount::new(100_000, token2);

            // Alice provides amount of Mob
            let input_credentials =
                get_input_credentials(block_version, amount, &alice, &fog_resolver, &mut rng);

            let proofs = input_credentials.membership_proofs.clone();
            let key_image = KeyImage::from(input_credentials.assert_has_onetime_private_key());

            let mut builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Alice requests amount2 worth of token id 2 in exchange
            let (_txout, _confirmation) = builder
                .add_required_output(amount2, &alice.default_subaddress(), &mut rng)
                .unwrap();

            let mut sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // The contingent input should have a valid signature.
            sci.validate().unwrap();
            assert_eq!(sci.key_image(), key_image);

            let mut builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, Mob::ID),
                fog_resolver,
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Bob adds the presigned input (raw), without adding required outputs
            sci.tx_in.proofs = proofs;
            builder.add_presigned_input_raw(sci);

            // Bob keeps the Mob that Alice supplies, less fees
            builder
                .add_output(
                    Amount::new(value - Mob::MINIMUM_FEE, Mob::ID),
                    &bob.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            builder.set_tombstone_block(1000);

            // The transaction is balanced, but it fails because all rings were presigned
            assert_matches!(
                builder.build(&NoKeysRingSigner {}, &mut rng),
                Err(TxBuilderError::RingSignatureFailed(
                    RingCtError::AllRingsPresigned
                ))
            );
        }
    }

    #[test]
    // Test that if you add a signed contingent input, but don't respect the rules
    // and try to send the required output to yourself, it fails with
    // MissingRequiredOutput.
    fn test_contingent_input_rules_ignoring_required_outputs_doesnt_work() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for block_version in 3..=*BlockVersion::MAX {
            let block_version = BlockVersion::try_from(block_version).unwrap();

            let alice = AccountKey::random(&mut rng);
            let bob = AccountKey::random_with_fog(&mut rng);
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);

            let fog_resolver = MockFogResolver(btreemap! {
                                bob
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
            let amount = Amount::new(value, Mob::ID);
            let token2 = TokenId::from(2);
            let amount2 = Amount::new(100_000, token2);
            let amount_meowb = Amount::new(1, 3.into());

            // Alice provides amount of Mob
            let input_credentials =
                get_input_credentials(block_version, amount, &alice, &fog_resolver, &mut rng);

            let proofs = input_credentials.membership_proofs.clone();
            let key_image = KeyImage::from(input_credentials.assert_has_onetime_private_key());

            let mut builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Alice requests amount2 worth of token id 2 in exchange
            let (_txout, _confirmation) = builder
                .add_required_output(amount2, &alice.default_subaddress(), &mut rng)
                .unwrap();

            let mut sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // The contingent input should have a valid signature.
            sci.validate().unwrap();
            assert_eq!(sci.key_image(), key_image);

            let mut builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, Mob::ID),
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Bob adds the presigned input (raw), without adding required outputs
            sci.tx_in.proofs = proofs;
            builder.add_presigned_input_raw(sci);

            // Bob adds a nominal amount of Meowblecoin, to avoid "all rings presigned"
            // error
            builder.add_input(get_input_credentials(
                block_version,
                amount_meowb,
                &bob,
                &fog_resolver,
                &mut rng,
            ));

            // Bob keeps the Mob that Alice supplies, less fees
            builder
                .add_output(
                    Amount::new(value - Mob::MINIMUM_FEE, Mob::ID),
                    &bob.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            // Bob pays back the nominal amount of meowb to himself, to have a balanced tx
            builder
                .add_output(amount_meowb, &bob.default_subaddress(), &mut rng)
                .unwrap();

            builder.set_tombstone_block(1000);

            // The transaction is balanced, so this should build
            let tx = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            assert_eq!(tx.prefix.tombstone_block, 1000);

            // tx does not pass input rule checks
            assert_matches!(
                validate_all_input_rules(block_version, &tx),
                Err(TransactionValidationError::InputRule(
                    InputRuleError::MissingRequiredOutput
                ))
            );
        }
    }

    #[test]
    // Test that if you add a signed contingent input, but don't respect the rules
    // and try to send the required output to yourself, it fails with
    // MissingRequiredOutput.
    fn test_contingent_input_rules_redirecting_required_outputs_doesnt_work() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for block_version in 3..=*BlockVersion::MAX {
            let block_version = BlockVersion::try_from(block_version).unwrap();

            let alice = AccountKey::random(&mut rng);
            let bob = AccountKey::random_with_fog(&mut rng);
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);

            let fog_resolver = MockFogResolver(btreemap! {
                                bob
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
            let amount = Amount::new(value, Mob::ID);
            let token2 = TokenId::from(2);
            let amount2 = Amount::new(100_000, token2);

            // Alice provides amount of Mob
            let input_credentials =
                get_input_credentials(block_version, amount, &alice, &fog_resolver, &mut rng);

            let proofs = input_credentials.membership_proofs.clone();
            let key_image = KeyImage::from(input_credentials.assert_has_onetime_private_key());

            let mut builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Alice requests amount2 worth of token id 2 in exchange
            let (_txout, _confirmation) = builder
                .add_required_output(amount2, &alice.default_subaddress(), &mut rng)
                .unwrap();

            let mut sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // The contingent input should have a valid signature.
            sci.validate().unwrap();
            assert_eq!(sci.key_image(), key_image);

            // Bob has 100_000 worth of token id 2
            let input_credentials =
                get_input_credentials(block_version, amount2, &bob, &fog_resolver, &mut rng);

            let mut builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, Mob::ID),
                fog_resolver,
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Bob adds the presigned input (raw), without adding required outputs
            sci.tx_in.proofs = proofs;
            builder.add_presigned_input_raw(sci);

            builder.add_input(input_credentials);

            // Bob keeps the Mob that Alice supplies, less fees
            builder
                .add_output(
                    Amount::new(value - Mob::MINIMUM_FEE, Mob::ID),
                    &bob.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            // Bob keeps the token id2 that he supplied also, instead of giving it to Alice
            builder
                .add_output(amount2, &bob.default_subaddress(), &mut rng)
                .unwrap();

            builder.set_tombstone_block(1000);

            // The transaction is balanced, so this should build
            let tx = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            assert_eq!(tx.prefix.tombstone_block, 1000);

            // tx does not pass input rule checks
            assert_matches!(
                validate_all_input_rules(block_version, &tx),
                Err(TransactionValidationError::InputRule(
                    InputRuleError::MissingRequiredOutput
                ))
            );
        }
    }

    #[test]
    // Test that if you add a signed contingent input, and give the user the value,
    // but don't give them the expected output, with expected memo etc., it
    // fails with MissingRequiredOutput.
    fn test_contingent_input_rules_sending_value_but_not_exact_required_output_doesnt_work() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for block_version in 3..=*BlockVersion::MAX {
            let block_version = BlockVersion::try_from(block_version).unwrap();

            let alice = AccountKey::random_with_fog(&mut rng);
            let bob = AccountKey::random(&mut rng);
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);

            let fog_resolver = MockFogResolver(btreemap! {
                                alice
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
            let amount = Amount::new(value, Mob::ID);
            let token2 = TokenId::from(2);
            let amount2 = Amount::new(100_000, token2);

            // Alice provides amount of Mob
            let input_credentials =
                get_input_credentials(block_version, amount, &alice, &fog_resolver, &mut rng);

            let proofs = input_credentials.membership_proofs.clone();
            let key_image = KeyImage::from(input_credentials.assert_has_onetime_private_key());

            let mut builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Alice requests amount2 worth of token id 2 in exchange
            builder
                .add_required_output(amount2, &alice.default_subaddress(), &mut rng)
                .unwrap();

            let mut sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // The contingent input should have a valid signature.
            sci.validate().unwrap();
            assert_eq!(sci.key_image(), key_image);

            let mut builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, Mob::ID),
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Bob adds the presigned input (raw), without adding required outputs
            sci.tx_in.proofs = proofs;
            builder.add_presigned_input_raw(sci);

            // Bob adds the token id 2 amount that alice requests
            builder.add_input(get_input_credentials(
                block_version,
                amount2,
                &bob,
                &fog_resolver,
                &mut rng,
            ));

            // Bob gives the value that alice requests (note, it's not the same output
            // actually)
            builder
                .add_output(amount2, &alice.default_subaddress(), &mut rng)
                .unwrap();

            // Bob keeps the Mob that Alice supplies, less fees
            builder
                .add_output(
                    Amount::new(value - Mob::MINIMUM_FEE, Mob::ID),
                    &bob.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            builder.set_tombstone_block(1000);

            // The transaction is balanced, so this should build
            let tx = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            assert_eq!(tx.prefix.tombstone_block, 1000);

            // tx does not pass input rule checks
            assert_matches!(
                validate_all_input_rules(block_version, &tx),
                Err(TransactionValidationError::InputRule(
                    InputRuleError::MissingRequiredOutput
                ))
            );
        }
    }

    #[test]
    // Test that if you delete the required output from a signed contingent input,
    // it fails with a ring signature error
    fn test_contingent_input_rules_modifying_required_output_rules_doesnt_work() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for block_version in 3..=*BlockVersion::MAX {
            let block_version = BlockVersion::try_from(block_version).unwrap();

            let alice = AccountKey::random_with_fog(&mut rng);
            let bob = AccountKey::random(&mut rng);
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);

            let fog_resolver = MockFogResolver(btreemap! {
                                alice
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
            let amount = Amount::new(value, Mob::ID);
            let token2 = TokenId::from(2);
            let amount2 = Amount::new(100_000, token2);

            // Alice provides amount of Mob
            let input_credentials =
                get_input_credentials(block_version, amount, &alice, &fog_resolver, &mut rng);

            let proofs = input_credentials.membership_proofs.clone();
            let key_image = KeyImage::from(input_credentials.assert_has_onetime_private_key());

            let mut builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Alice requests amount2 worth of token id 2 in exchange
            let (_txout, _confirmation) = builder
                .add_required_output(amount2, &alice.default_subaddress(), &mut rng)
                .unwrap();

            let mut sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // The contingent input should have a valid signature.
            sci.validate().unwrap();
            assert_eq!(sci.key_image(), key_image);

            // Now we modify it to remove the required output
            sci.tx_in
                .input_rules
                .as_mut()
                .unwrap()
                .required_outputs
                .clear();

            // (Sanity check: the sci fails its own validation now, because the signature is
            // invalid)
            assert_matches!(
                sci.validate(),
                Err(SignedContingentInputError::RingSignature(_))
            );

            let mut builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, Mob::ID),
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Bob adds the presigned input (raw), without adding required outputs
            sci.tx_in.proofs = proofs;
            builder.add_presigned_input_raw(sci);

            // Bob adds the token id 2 amount that alice requests
            builder.add_input(get_input_credentials(
                block_version,
                amount2,
                &bob,
                &fog_resolver,
                &mut rng,
            ));

            // Bob gives the value that alice requests (note, it's not the same output
            // actually)
            builder
                .add_output(amount2, &alice.default_subaddress(), &mut rng)
                .unwrap();

            // Bob keeps the Mob that Alice supplies, less fees
            builder
                .add_output(
                    Amount::new(value - Mob::MINIMUM_FEE, Mob::ID),
                    &bob.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            builder.set_tombstone_block(1000);

            // The transaction is balanced, so this should build
            let tx = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            assert_eq!(tx.prefix.tombstone_block, 1000);

            // tx does pass input rule checks (we deleted the rules)
            validate_all_input_rules(block_version, &tx).unwrap();
            // tx fails signature check (one signature is over the rules we deleted)
            assert_matches!(
                validate_signature(block_version, &tx, &mut rng),
                Err(TransactionValidationError::InvalidTransactionSignature(_))
            );
        }
    }

    #[test]
    // Test that if you delete the input rules entirely from a signed contingent
    // input, it fails with a ring signature error
    fn test_contingent_input_rules_deleting_all_input_rules_doesnt_work() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for block_version in 3..=*BlockVersion::MAX {
            let block_version = BlockVersion::try_from(block_version).unwrap();

            let alice = AccountKey::random_with_fog(&mut rng);
            let bob = AccountKey::random(&mut rng);
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);

            let fog_resolver = MockFogResolver(btreemap! {
                                alice
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
            let amount = Amount::new(value, Mob::ID);
            let token2 = TokenId::from(2);
            let amount2 = Amount::new(100_000, token2);

            // Alice provides amount of Mob
            let input_credentials =
                get_input_credentials(block_version, amount, &alice, &fog_resolver, &mut rng);

            let proofs = input_credentials.membership_proofs.clone();
            let key_image = KeyImage::from(input_credentials.assert_has_onetime_private_key());

            let mut builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Alice requests amount2 worth of token id 2 in exchange
            let (_txout, _confirmation) = builder
                .add_required_output(amount2, &alice.default_subaddress(), &mut rng)
                .unwrap();

            let mut sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // The contingent input should have a valid signature.
            sci.validate().unwrap();
            assert_eq!(sci.key_image(), key_image);

            // Now we modify it to remove the input rules entirely
            sci.tx_in.input_rules = None;

            // (Sanity check: the sci fails its own validation now, because the rules are
            // missing)
            assert_matches!(
                sci.validate(),
                Err(SignedContingentInputError::MissingRules)
            );

            let mut builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, Mob::ID),
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Bob adds the presigned input (raw), without adding required outputs
            sci.tx_in.proofs = proofs;
            builder.add_presigned_input_raw(sci);

            // Bob adds the token id 2 amount that alice requests
            builder.add_input(get_input_credentials(
                block_version,
                amount2,
                &bob,
                &fog_resolver,
                &mut rng,
            ));

            // Bob gives the value that alice requests (note, it's not the same output
            // actually)
            builder
                .add_output(amount2, &alice.default_subaddress(), &mut rng)
                .unwrap();

            // Bob keeps the Mob that Alice supplies, less fees
            builder
                .add_output(
                    Amount::new(value - Mob::MINIMUM_FEE, Mob::ID),
                    &bob.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            builder.set_tombstone_block(1000);

            // The transaction is balanced, so this should build
            let tx = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            assert_eq!(tx.prefix.tombstone_block, 1000);

            // tx does pass input rule checks (we deleted the rules)
            validate_all_input_rules(block_version, &tx).unwrap();
            // tx fails signature check (one signature is over the rules we deleted)
            assert_matches!(
                validate_signature(block_version, &tx, &mut rng),
                Err(TransactionValidationError::InvalidTransactionSignature(_))
            );
        }
    }

    #[test]
    // Test that if you add a signed contingent input, but don't respect tombstone
    // block rules, it fails with MaxTombstoneBlockExceeded
    fn test_contingent_input_rules_ignoring_tombstone_block_doesnt_work() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for block_version in 3..=*BlockVersion::MAX {
            let block_version = BlockVersion::try_from(block_version).unwrap();

            let alice = AccountKey::random_with_fog(&mut rng);
            let bob = AccountKey::random(&mut rng);
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);

            let fog_resolver = MockFogResolver(btreemap! {
                                alice
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
            let amount = Amount::new(value, Mob::ID);
            let token2 = TokenId::from(2);
            let amount2 = Amount::new(100_000, token2);

            // Alice provides amount of Mob
            let input_credentials =
                get_input_credentials(block_version, amount, &alice, &fog_resolver, &mut rng);

            let proofs = input_credentials.membership_proofs.clone();
            let key_image = KeyImage::from(input_credentials.assert_has_onetime_private_key());

            let mut builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Alice requests amount2 worth of token id 2 in exchange
            builder
                .add_required_output(amount2, &alice.default_subaddress(), &mut rng)
                .unwrap();

            let mut sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // The contingent input should have a valid signature.
            sci.validate().unwrap();
            assert_eq!(sci.key_image(), key_image);

            let mut builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, Mob::ID),
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Bob adds the presigned input (raw), without adding required outputs
            sci.tx_in.proofs = proofs;
            builder.add_presigned_input_raw(sci);

            // Bob adds the token id 2 amount that alice requests
            builder.add_input(get_input_credentials(
                block_version,
                amount2,
                &bob,
                &fog_resolver,
                &mut rng,
            ));

            // Bob keeps the value that alice requests
            builder
                .add_output(amount2, &bob.default_subaddress(), &mut rng)
                .unwrap();

            // Bob keeps the Mob that Alice supplies, less fees
            builder
                .add_output(
                    Amount::new(value - Mob::MINIMUM_FEE, Mob::ID),
                    &bob.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            // Bob also doesn't respect Alice's tombstone block limit of 2000
            builder.set_tombstone_block(2000);

            // The transaction is balanced, so this should build
            let tx = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            assert_eq!(tx.prefix.tombstone_block, 2000);

            // tx does not pass input rule checks
            assert_matches!(
                validate_all_input_rules(block_version, &tx),
                Err(TransactionValidationError::InputRule(
                    InputRuleError::MaxTombstoneBlockExceeded
                ))
            );
        }
    }

    #[test]
    // Test that if you add a signed contingent input, but don't respect tombstone
    // block rules, and modify tombstone block rules, it fails with Ring
    // signature error
    fn test_contingent_input_rules_modifying_tombstone_block_rules_doesnt_work() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for block_version in 3..=*BlockVersion::MAX {
            let block_version = BlockVersion::try_from(block_version).unwrap();

            let alice = AccountKey::random_with_fog(&mut rng);
            let bob = AccountKey::random(&mut rng);
            let ingest_private_key = RistrettoPrivate::from_random(&mut rng);

            let fog_resolver = MockFogResolver(btreemap! {
                                alice
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
            let amount = Amount::new(value, Mob::ID);
            let token2 = TokenId::from(2);
            let amount2 = Amount::new(100_000, token2);

            // Alice provides amount of Mob
            let input_credentials =
                get_input_credentials(block_version, amount, &alice, &fog_resolver, &mut rng);

            let proofs = input_credentials.membership_proofs.clone();
            let key_image = KeyImage::from(input_credentials.assert_has_onetime_private_key());

            let mut builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Alice requests amount2 worth of token id 2 in exchange
            builder
                .add_required_output(amount2, &alice.default_subaddress(), &mut rng)
                .unwrap();

            let mut sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // The contingent input should have a valid signature.
            sci.validate().unwrap();
            assert_eq!(sci.key_image(), key_image);
            assert_eq!(
                sci.tx_in.input_rules.as_mut().unwrap().max_tombstone_block,
                1000
            );

            // Now we modify it to increase the max tombstone block limit
            sci.tx_in.input_rules.as_mut().unwrap().max_tombstone_block = 2000;

            // (Sanity check: the sci fails its own validation now, because the signature is
            // invalid)
            assert_matches!(
                sci.validate(),
                Err(SignedContingentInputError::RingSignature(_))
            );

            let mut builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, Mob::ID),
                fog_resolver.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            // Bob adds the presigned input (raw), without adding required outputs
            sci.tx_in.proofs = proofs;
            builder.add_presigned_input_raw(sci);

            // Bob adds the token id 2 amount that alice requests
            builder.add_input(get_input_credentials(
                block_version,
                amount2,
                &bob,
                &fog_resolver,
                &mut rng,
            ));

            // Bob keeps the value that alice requests
            builder
                .add_output(amount2, &bob.default_subaddress(), &mut rng)
                .unwrap();

            // Bob keeps the Mob that Alice supplies, less fees
            builder
                .add_output(
                    Amount::new(value - Mob::MINIMUM_FEE, Mob::ID),
                    &bob.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            // Bob also doesn't respect Alice's tombstone block limit of 2000
            builder.set_tombstone_block(2000);

            // The transaction is balanced, so this should build
            let tx = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            assert_eq!(tx.prefix.tombstone_block, 2000);

            // tx doesn't complain about tombstone block since we changed the rules, now
            // complains about missing required outputs
            assert_matches!(
                validate_all_input_rules(block_version, &tx),
                Err(TransactionValidationError::InputRule(
                    InputRuleError::MissingRequiredOutput
                ))
            );
            // tx fails signature check (one signature is over the rules we deleted)
            assert_matches!(
                validate_signature(block_version, &tx, &mut rng),
                Err(TransactionValidationError::InvalidTransactionSignature(_))
            );
        }
    }
}
