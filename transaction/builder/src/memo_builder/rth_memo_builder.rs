// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Defines the RTHMemoBuilder.
//! (RTH is an abbrevation of Recoverable Transaction History.)
//! This MemoBuilder policy implements Recoverable Transaction History using
//! the encrypted memos, as envisioned in MCIP #4.
use super::MemoBuilder;
use crate::ReservedSubaddresses;
use alloc::{fmt::Debug, format, string::String};
use displaydoc::Display;
use mc_account_keys::{PublicAddress, ShortAddressHash};
use mc_transaction_core::{
    tokens::Mob, Amount, MemoContext, MemoPayload, NewMemoError, Token, TokenId,
};
use mc_transaction_extra::{
    compute_authenticated_sender_memo, compute_destination_memo, AuthenticatedSenderMemo,
    AuthenticatedSenderWithPaymentIntentIdMemo, AuthenticatedSenderWithPaymentRequestIdMemo,
    DestinationMemo, DestinationMemoError, DestinationWithPaymentIntentIdMemo,
    DestinationWithPaymentRequestIdMemo, SenderMemoCredential, UnusedMemo,
};

/// This memo builder attaches 0x0100 Authenticated Sender Memos to normal
/// outputs, and 0x0200 Destination Memos to change outputs.
///
/// Usage:
/// You should usually use this like:
///
///   let mut mb = RTHMemoBuilder::default();
///   mb.set_sender_credential(SenderMemoCredential::from(&account_key);
///   mb.enable_destination_memo();
///
/// Then use it to construct a transaction builder.
///
/// A memo builder configured this way will use 0x0100 Authenticated Sender Memo
/// on regular outputs and 0x0200 Destination Memo on change outputs.
///
/// If you have a payment request id, you specify it like this:
///
///   mb.set_payment_request_id(request_id);
///
/// If a payment request id is specified, then 0x0101 Authenticated Sender With
/// Payment Request Id Memo is used instead of 0x0100.
///
/// If no sender credential is provided then 0x0000 Unused will appear on
/// regular outputs.
///
/// If mb.enable_destination_memo() is not called 0x0000 Unused will appear on
/// change outputs, instead of 0x0200 Destination Memo.
///
/// When invoking the transaction builder, the change output must be created
/// last. If a normal output is created after the change output, an error will
/// occur.
///
/// If more than one normal output is created, only the last recipient's public
/// address will be recorded in the 0x0200 Destination Memo.
#[derive(Clone, Debug)]
pub struct RTHMemoBuilder {
    // The credential used to form 0x0100 and 0x0101 memos, if present.
    sender_cred: Option<SenderMemoCredential>,
    // Different options for the custom memo data
    custom_memo_type: Option<CustomMemoType>,
    // Whether destination memos are enabled.
    destination_memo_enabled: bool,
    // Tracks if we already wrote a destination memo, for error reporting
    wrote_destination_memo: bool,
    // Tracks the last recipient
    last_recipient: ShortAddressHash,
    // Tracks the total outlay so far
    total_outlay: u64,
    // Tracks the total outlay token id
    outlay_token_id: Option<TokenId>,
    // Tracks the number of recipients so far
    num_recipients: u8,
    // Tracks the fee
    fee: Amount,
}

#[derive(Clone, Debug)]
pub enum CustomMemoType {
    PaymentRequestId(u64),
    PaymentIntentId(u64),
    FlexibleMemos(FlexibleMemoPayloads),
}

/// This contains both the output memo payload and the change memo payload which
/// will be used when generating custom output memos and change memos
#[derive(Clone, Debug)]
pub struct FlexibleMemoPayloads {
    /// This is used when generating output memos.
    /// It must contain a memo type with the first byte being 0x01
    pub output_memo_payload: FlexibleMemoPayload,
    /// This is used when generating change memos.
    /// It must contain a memo type with the first byte being 0x02
    pub change_memo_payload: FlexibleMemoPayload,
}

/// This is the payload data used for creating custom MemoPayloads with types
/// which are defined in MCIPs.
#[derive(Clone, Debug)]
pub struct FlexibleMemoPayload {
    /// memo_type_bytes corresponds to the returned memo type. This should be
    /// listed in an MCIP.
    pub memo_type_bytes: [u8; 2],
    /// memo_data: corresponds to some 32 byte encoding of data used for
    /// the returned memo type, and does not include fields used for the
    /// authenticated sender or destination super types like the
    /// SenderMemoCredential
    pub memo_data: [u8; 32],
}

impl Default for RTHMemoBuilder {
    fn default() -> Self {
        Self {
            sender_cred: Default::default(),
            custom_memo_type: None,
            destination_memo_enabled: false,
            wrote_destination_memo: false,
            last_recipient: Default::default(),
            total_outlay: 0,
            outlay_token_id: None,
            num_recipients: 0,
            fee: Amount::new(Mob::MINIMUM_FEE, Mob::ID),
        }
    }
}

/// An error that occurs when setting up a memo builder
///
/// These errors are usually created setting invalid field combinations on the
/// memo builder. We have included error codes for some known useful error
/// conditions. For a custom MemoBuilder, you can try to reuse those, or use the
/// Other error code.
#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum MemoBuilderError {
    /// Invalid state change
    StateChange(String),
    /// Other
    Other(String),
}

impl RTHMemoBuilder {
    /// Set the sender credential. If no sender credential is provided,
    /// then authenticated sender memos cannot be produced.
    ///
    /// This credential usually be produced from your AccountKey object.
    ///
    /// If you want to make it appear to the recipient as if this came from
    /// another address or a subaddress of yours,
    /// you can do that as long as you have the spend private key
    /// for that address.
    ///
    /// For example, if you are an exchange, and you are sending
    /// MOB to a user, you might set this to match the subaddress that they
    /// normally deposit to. Then a chat client will be able to associate both
    /// their deposits and withdrawals into a single chat interaction.
    pub fn set_sender_credential(&mut self, cred: SenderMemoCredential) {
        self.sender_cred = Some(cred);
    }

    /// Clear the sender credential.
    pub fn clear_sender_credential(&mut self) {
        self.sender_cred = None;
    }

    /// Set the payment request id.
    pub fn set_payment_request_id(&mut self, id: u64) -> Result<(), MemoBuilderError> {
        if self.custom_memo_type.is_some() {
            return Err(MemoBuilderError::StateChange(format!(
                "Custom Memo Type already set to {:?}",
                self.custom_memo_type
            )));
        }
        self.custom_memo_type = Some(CustomMemoType::PaymentRequestId(id));
        Ok(())
    }

    /// Clear the custom memo type.
    pub fn clear_custom_memo_type(&mut self) {
        self.custom_memo_type = None;
    }

    /// Set the payment intent id.
    pub fn set_payment_intent_id(&mut self, id: u64) -> Result<(), MemoBuilderError> {
        if self.custom_memo_type.is_some() {
            return Err(MemoBuilderError::StateChange(format!(
                "Custom Memo Type already set to {:?}",
                self.custom_memo_type
            )));
        }
        self.custom_memo_type = Some(CustomMemoType::PaymentIntentId(id));
        Ok(())
    }

    /// Set the flexible memos.
    pub fn set_flexible_memos(
        &mut self,
        memos: FlexibleMemoPayloads,
    ) -> Result<(), MemoBuilderError> {
        if self.custom_memo_type.is_some() {
            return Err(MemoBuilderError::StateChange(format!(
                "Custom Memo Type already set to {:?}",
                self.custom_memo_type
            )));
        }
        self.custom_memo_type = Some(CustomMemoType::FlexibleMemos(memos));
        Ok(())
    }

    /// Enable destination memos
    pub fn enable_destination_memo(&mut self) {
        self.destination_memo_enabled = true;
    }

    /// Disable destination memos
    pub fn disable_destination_memo(&mut self) {
        self.destination_memo_enabled = false;
    }
}

impl MemoBuilder for RTHMemoBuilder {
    /// Set the fee
    fn set_fee(&mut self, fee: Amount) -> Result<(), NewMemoError> {
        if self.wrote_destination_memo {
            return Err(NewMemoError::FeeAfterChange);
        }
        self.fee = fee;
        Ok(())
    }

    /// Build a memo for a normal output (to another party).
    fn make_memo_for_output(
        &mut self,
        amount: Amount,
        recipient: &PublicAddress,
        memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if self.wrote_destination_memo {
            return Err(NewMemoError::OutputsAfterChange);
        }
        // Check if the outlay is mixing token ids
        if let Some(prev_token_id) = self.outlay_token_id {
            if prev_token_id != amount.token_id {
                return Err(NewMemoError::MixedTokenIds);
            }
        } else {
            // If this is the first outlay, then this is the token id for the whole outlay.
            self.outlay_token_id = Some(amount.token_id);
        }
        self.total_outlay = self
            .total_outlay
            .checked_add(amount.value)
            .ok_or(NewMemoError::LimitsExceeded("total_outlay"))?;
        self.num_recipients = self
            .num_recipients
            .checked_add(1)
            .ok_or(NewMemoError::LimitsExceeded("num_recipients"))?;
        self.last_recipient = ShortAddressHash::from(recipient);

        let payload: MemoPayload = if let Some(cred) = &self.sender_cred {
            if let Some(custom_memo_type) = &self.custom_memo_type {
                match custom_memo_type {
                    CustomMemoType::FlexibleMemos(flexible_memos) => {
                        let tx_public_key = memo_context.tx_public_key;
                        let flexible_memo_payload = &flexible_memos.output_memo_payload;
                        let memo_data = compute_authenticated_sender_memo(
                            flexible_memo_payload.memo_type_bytes,
                            cred,
                            recipient.view_public_key(),
                            &tx_public_key.into(),
                            &flexible_memo_payload.memo_data,
                        );
                        if flexible_memo_payload.memo_type_bytes[0] != 0x01 {
                            return Err(NewMemoError::FlexibleMemo(format!("The flexible output memo has a memopayload of the incorrect memo type: {:?}", flexible_memo_payload.memo_type_bytes)));
                        }
                        MemoPayload::new(flexible_memo_payload.memo_type_bytes, memo_data)
                    }
                    CustomMemoType::PaymentRequestId(payment_request_id) => {
                        AuthenticatedSenderWithPaymentRequestIdMemo::new(
                            cred,
                            recipient.view_public_key(),
                            &memo_context.tx_public_key.into(),
                            *payment_request_id,
                        )
                        .into()
                    }
                    CustomMemoType::PaymentIntentId(payment_intent_id) => {
                        AuthenticatedSenderWithPaymentIntentIdMemo::new(
                            cred,
                            recipient.view_public_key(),
                            &memo_context.tx_public_key.into(),
                            *payment_intent_id,
                        )
                        .into()
                    }
                }
            } else {
                AuthenticatedSenderMemo::new(
                    cred,
                    recipient.view_public_key(),
                    &memo_context.tx_public_key.into(),
                )
                .into()
            }
        } else {
            UnusedMemo {}.into()
        };
        Ok(payload)
    }

    /// Build a memo for a change output (to ourselves).
    fn make_memo_for_change_output(
        &mut self,
        amount: Amount,
        _change_destination: &ReservedSubaddresses,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if !self.destination_memo_enabled {
            return Ok(UnusedMemo {}.into());
        }
        if self.wrote_destination_memo {
            return Err(NewMemoError::MultipleChangeOutputs);
        }
        // Check if the outlay is mixing token ids
        if let Some(prev_token_id) = self.outlay_token_id {
            if prev_token_id != amount.token_id {
                return Err(NewMemoError::MixedTokenIds);
            }
        } else {
            // If no outlays occurred yet, this should be the token id for the whole tx.
            self.outlay_token_id = Some(amount.token_id);
        }

        // If the fee is not the same token id as the outlay, then
        // total_outlay.checked_add(self.fee.value) is wrong.
        // We need to specify token-id aware RTH memos
        if self.fee.token_id != amount.token_id {
            return Err(NewMemoError::MixedTokenIds);
        }

        if self.fee.value.to_be_bytes()[0] != 0u8 {
            return Err(NewMemoError::LimitsExceeded("fee"));
        }

        self.total_outlay = self
            .total_outlay
            .checked_add(self.fee.value)
            .ok_or(NewMemoError::LimitsExceeded("total_outlay"))?;
        if let Some(custom_memo_type) = &self.custom_memo_type {
            match custom_memo_type {
                CustomMemoType::FlexibleMemos(flexible_memos) => {
                    let flexible_memo_payload = &flexible_memos.change_memo_payload;
                    if flexible_memo_payload.memo_type_bytes[0] != 0x02 {
                        return Err(NewMemoError::FlexibleMemo(format!("The flexible change memo has a memopayload of the incorrect memo type: {:?}", flexible_memo_payload.memo_type_bytes)));
                    }
                    let memo_data = compute_destination_memo(
                        self.last_recipient.clone(),
                        self.fee.value,
                        self.num_recipients,
                        self.total_outlay,
                        flexible_memo_payload.memo_data,
                    );
                    let payload: MemoPayload =
                        MemoPayload::new(flexible_memo_payload.memo_type_bytes, memo_data);
                    self.wrote_destination_memo = true;
                    Ok(payload)
                }
                CustomMemoType::PaymentRequestId(payment_request_id) => {
                    match DestinationWithPaymentRequestIdMemo::new(
                        self.last_recipient.clone(),
                        self.total_outlay,
                        self.fee.value,
                        *payment_request_id,
                    ) {
                        Ok(mut d_memo) => {
                            self.wrote_destination_memo = true;
                            d_memo.set_num_recipients(self.num_recipients);
                            Ok(d_memo.into())
                        }
                        Err(err) => match err {
                            DestinationMemoError::FeeTooLarge => {
                                Err(NewMemoError::LimitsExceeded("fee"))
                            }
                        },
                    }
                }
                CustomMemoType::PaymentIntentId(payment_intent_id) => {
                    match DestinationWithPaymentIntentIdMemo::new(
                        self.last_recipient.clone(),
                        self.total_outlay,
                        self.fee.value,
                        *payment_intent_id,
                    ) {
                        Ok(mut d_memo) => {
                            self.wrote_destination_memo = true;
                            d_memo.set_num_recipients(self.num_recipients);
                            Ok(d_memo.into())
                        }
                        Err(err) => match err {
                            DestinationMemoError::FeeTooLarge => {
                                Err(NewMemoError::LimitsExceeded("fee"))
                            }
                        },
                    }
                }
            }
        } else {
            match DestinationMemo::new(
                self.last_recipient.clone(),
                self.total_outlay,
                self.fee.value,
            ) {
                Ok(mut d_memo) => {
                    self.wrote_destination_memo = true;
                    d_memo.set_num_recipients(self.num_recipients);
                    Ok(d_memo.into())
                }
                Err(err) => match err {
                    DestinationMemoError::FeeTooLarge => Err(NewMemoError::LimitsExceeded("fee")),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::AccountKey;
    use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
    use mc_transaction_extra::{
        get_data_from_authenticated_sender_memo, get_data_from_destination_memo,
        validate_authenticated_sender, RegisteredMemoType,
    };
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    const AUTHENTICATED_CUSTOM_MEMO_TYPE_BYTES: [u8; 2] = [0x01, 0x08];
    const DESTINATION_CUSTOM_MEMO_TYPE_BYTES: [u8; 2] = [0x02, 0x08];

    pub struct RTHMemoTestContext {
        sender: AccountKey,
        receiver: AccountKey,
        funding_public_key: RistrettoPublic,
        output_memo: Result<MemoPayload, NewMemoError>,
        change_memo: Result<MemoPayload, NewMemoError>,
    }

    fn get_valid_flexible_memos() -> FlexibleMemoPayloads {
        let memo_type_bytes = AUTHENTICATED_CUSTOM_MEMO_TYPE_BYTES;
        let memo_data = [0x01; 32];
        let output_memo_payload = FlexibleMemoPayload {
            memo_type_bytes,
            memo_data,
        };
        let memo_type_bytes = DESTINATION_CUSTOM_MEMO_TYPE_BYTES;
        let memo_data = [0x01; 32];
        let change_memo_payload = FlexibleMemoPayload {
            memo_type_bytes,
            memo_data,
        };
        FlexibleMemoPayloads {
            output_memo_payload,
            change_memo_payload,
        }
    }
    fn get_invalid_flexible_memos() -> FlexibleMemoPayloads {
        let memo_type_bytes = DESTINATION_CUSTOM_MEMO_TYPE_BYTES;
        let memo_data = [0x01; 32];
        let output_memo_payload = FlexibleMemoPayload {
            memo_type_bytes,
            memo_data,
        };
        let memo_type_bytes = AUTHENTICATED_CUSTOM_MEMO_TYPE_BYTES;
        let memo_data = [0x01; 32];
        let change_memo_payload = FlexibleMemoPayload {
            memo_type_bytes,
            memo_data,
        };
        FlexibleMemoPayloads {
            output_memo_payload,
            change_memo_payload,
        }
    }

    fn build_rth_memos(
        sender: AccountKey,
        mut builder: RTHMemoBuilder,
        funding_amount: Amount,
        change_amount: Amount,
        fee: Amount,
    ) -> RTHMemoTestContext {
        // Create simulated context
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let sender_address_book = ReservedSubaddresses::from(&sender);

        let receiver = AccountKey::random_with_fog(&mut rng);
        let receiver_primary_address = receiver.default_subaddress();

        let funding_public_key = RistrettoPublic::from_random(&mut rng);
        let funding_context = MemoContext {
            tx_public_key: &funding_public_key,
        };
        let change_tx_pubkey = RistrettoPublic::from_random(&mut rng);
        let change_context = MemoContext {
            tx_public_key: &change_tx_pubkey,
        };

        builder.set_fee(fee).unwrap();
        // Build blank output memo for TxOut at gift code address & funding memo to
        // change output
        let output_memo = builder.make_memo_for_output(
            funding_amount,
            &receiver_primary_address,
            funding_context,
        );
        let change_memo = builder.make_memo_for_change_output(
            change_amount,
            &sender_address_book,
            change_context,
        );
        RTHMemoTestContext {
            sender,
            receiver,
            funding_public_key,
            output_memo,
            change_memo,
        }
    }

    fn build_test_memo_builder(rng: &mut StdRng) -> (AccountKey, RTHMemoBuilder) {
        let sender = AccountKey::random(rng);
        let mut memo_builder = RTHMemoBuilder::default();
        memo_builder.set_sender_credential(SenderMemoCredential::from(&sender));
        memo_builder.enable_destination_memo();
        (sender, memo_builder)
    }

    #[test]
    fn test_funding_memo_built_successfully() {
        // Create Memo Builder with data
        let fee = Amount::new(1, 0.into());
        let change_amount = Amount::new(1, 0.into());
        let funding_amount = Amount::new(10, 0.into());

        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let (sender, builder) = build_test_memo_builder(&mut rng);
        // Build the memo payload
        let memo_test_context =
            build_rth_memos(sender, builder, funding_amount, change_amount, fee);

        let output_memo = memo_test_context
            .output_memo
            .expect("Expected valid output memo");
        let change_memo = memo_test_context
            .change_memo
            .expect("Expected valid change memo");

        // Verify memo type
        assert_eq!(
            AuthenticatedSenderMemo::MEMO_TYPE_BYTES,
            output_memo.get_memo_type().clone()
        );
        assert_eq!(
            DestinationMemo::MEMO_TYPE_BYTES,
            change_memo.get_memo_type().clone()
        );

        // Verify memo data
        let authenticated_memo = AuthenticatedSenderMemo::from(output_memo.get_memo_data());
        let destination_memo = DestinationMemo::from(change_memo.get_memo_data());

        authenticated_memo.validate(
            &memo_test_context.sender.default_subaddress(),
            memo_test_context.receiver.view_private_key(),
            &CompressedRistrettoPublic::from(memo_test_context.funding_public_key),
        );

        let derived_fee = destination_memo.get_fee();
        assert_eq!(fee.value, derived_fee);
    }

    #[test]
    fn test_funding_memo_rejects_fees_which_are_too_large() {
        // Create Memo Builder with data
        let fee = Amount::new(u64::MAX, 0.into());
        let change_amount = Amount::new(1, 0.into());
        let funding_amount = Amount::new(10, 0.into());

        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let (sender, builder) = build_test_memo_builder(&mut rng);
        // Build the memo payload
        let memo_test_context =
            build_rth_memos(sender, builder, funding_amount, change_amount, fee);
        assert_eq!(
            memo_test_context
                .change_memo
                .expect_err("Should have an invalid destination memo type"),
            NewMemoError::LimitsExceeded("fee")
        );
    }

    #[test]
    fn test_flexible_funding_output_memo_built_successfully() {
        // Create Memo Builder with data
        let fee = Amount::new(1, 0.into());
        let change_amount = Amount::new(1, 0.into());
        let funding_amount = Amount::new(10, 0.into());

        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let (sender, mut builder) = build_test_memo_builder(&mut rng);
        // Add a flexible memo
        builder
            .set_flexible_memos(get_valid_flexible_memos())
            .expect("No other custom memo type should be set");
        // Build the memo payload
        let memo_test_context =
            build_rth_memos(sender, builder, funding_amount, change_amount, fee);

        let output_memo = memo_test_context
            .output_memo
            .expect("Expected valid output memo");
        let change_memo = memo_test_context
            .change_memo
            .expect("Expected valid change memo");

        // Verify memo type
        assert_eq!(
            AUTHENTICATED_CUSTOM_MEMO_TYPE_BYTES,
            output_memo.get_memo_type().clone()
        );
        assert_eq!(
            DESTINATION_CUSTOM_MEMO_TYPE_BYTES,
            change_memo.get_memo_type().clone()
        );

        // Verify memo data
        let destination_memo = DestinationMemo::from(change_memo.get_memo_data());

        validate_authenticated_sender(
            &memo_test_context.sender.default_subaddress(),
            memo_test_context.receiver.view_private_key(),
            &CompressedRistrettoPublic::from(memo_test_context.funding_public_key),
            *output_memo.get_memo_type(),
            output_memo.get_memo_data(),
        );

        let derived_fee = destination_memo.get_fee();
        assert_eq!(fee.value, derived_fee);

        assert_eq!(
            get_data_from_authenticated_sender_memo(output_memo.get_memo_data()),
            [1u8; 32]
        );
        assert_eq!(
            get_data_from_destination_memo(change_memo.get_memo_data()),
            [1u8; 32]
        );
    }

    #[test]
    fn test_flexible_funding_output_memo_rejects_invalid_types() {
        // Create Memo Builder with data
        let fee = Amount::new(1, 0.into());
        let change_amount = Amount::new(1, 0.into());
        let funding_amount = Amount::new(10, 0.into());

        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let (sender, mut builder) = build_test_memo_builder(&mut rng);
        // Add a flexible memo
        builder
            .set_flexible_memos(get_invalid_flexible_memos())
            .expect("No other custom memo types should be set");
        // Build the memo payload
        let memo_test_context =
            build_rth_memos(sender, builder, funding_amount, change_amount, fee);

        assert_eq!(
            memo_test_context
                .output_memo
                .expect_err("Should have an invalid output memo type"),
            NewMemoError::FlexibleMemo(
                "The flexible output memo has a memopayload of the incorrect memo type: [2, 8]"
                    .to_owned()
            )
        );
        assert_eq!(
            memo_test_context
                .change_memo
                .expect_err("Should have an invalid destination memo type"),
            NewMemoError::FlexibleMemo(
                "The flexible change memo has a memopayload of the incorrect memo type: [1, 8]"
                    .to_owned()
            )
        );
    }
}
