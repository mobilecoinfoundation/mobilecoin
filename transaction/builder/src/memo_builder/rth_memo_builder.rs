// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Defines the RTHMemoBuilder.
//! (RTH is an abbrevation of Recoverable Transaction History.)
//! This MemoBuilder policy implements Recoverable Transaction History using
//! the encrypted memos, as envisioned in MCIP #4.

use super::MemoBuilder;
use crate::ReservedSubaddresses;
use alloc::{boxed::Box, sync::Arc};
use core::fmt::Debug;
use mc_account_keys::{PublicAddress, ShortAddressHash};
use mc_transaction_core::{
    tokens::Mob, Amount, MemoContext, MemoPayload, NewMemoError, Token, TokenId,
};
use mc_transaction_extra::{
    AuthenticatedMemoHmacSigner, AuthenticatedSenderMemo,
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
    /// The authenticated sender hmac signer used when forming 0x0100 and 0x0101
    /// memos. If not present, no authenticated sender memos will be formed.
    authenticated_sender_hmac_signer:
        Option<Arc<Box<dyn AuthenticatedMemoHmacSigner + 'static + Send + Sync>>>,
    /// The payment request id, if any
    payment_request_id: Option<u64>,
    /// The payment intent id, if any
    payment_intent_id: Option<u64>,
    /// Whether destination memos are enabled.
    destination_memo_enabled: bool,
    /// Tracks if we already wrote a destination memo, for error reporting
    wrote_destination_memo: bool,
    /// Tracks the last recipient
    last_recipient: ShortAddressHash,
    /// Tracks the total outlay so far
    total_outlay: u64,
    /// Tracks the total outlay token id
    outlay_token_id: Option<TokenId>,
    /// Tracks the number of recipients so far
    num_recipients: u8,
    /// Tracks the fee
    fee: Amount,
}

impl Default for RTHMemoBuilder {
    fn default() -> Self {
        Self {
            authenticated_sender_hmac_signer: Default::default(),
            payment_request_id: None,
            payment_intent_id: None,
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

impl RTHMemoBuilder {
    /// Set the sender credential. If no sender credential is provided,
    /// then authenticated sender memos will not be produced.
    /// This is the same as calling set_authenticated_sender_hmac_signer with
    /// `Arc::new(Box::new(cred))` and is provided for convenience.
    ///
    /// This credential is usually produced from your AccountKey object.
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
        self.authenticated_sender_hmac_signer = Some(Arc::new(Box::new(cred)));
    }

    /// Set the authenticated sender hmac signer. If no authenticated sender
    /// hmac signer is provided, then authenticated sender memos cannot be
    /// produced.
    pub fn set_authenticated_sender_hmac_signer(
        &mut self,
        hmac_signer: impl Into<
            Option<Arc<Box<dyn AuthenticatedMemoHmacSigner + 'static + Send + Sync>>>,
        >,
    ) {
        self.authenticated_sender_hmac_signer = hmac_signer.into();
    }

    /// Set the payment request id.
    pub fn set_payment_request_id(&mut self, id: u64) {
        self.payment_request_id = Some(id);
    }

    /// Clear the payment request id.
    pub fn clear_payment_request_id(&mut self) {
        self.payment_request_id = None;
    }

    /// Set the payment intent id.
    pub fn set_payment_intent_id(&mut self, id: u64) {
        self.payment_intent_id = Some(id);
    }

    /// Clear the payment intent id.
    pub fn clear_payment_intent_id(&mut self) {
        self.payment_intent_id = None;
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

        let payload: MemoPayload = if let Some(hmac_signer) = &self.authenticated_sender_hmac_signer
        {
            if self.payment_request_id.is_some() && self.payment_intent_id.is_some() {
                return Err(NewMemoError::RequestAndIntentIdSet);
            }
            if let Some(payment_request_id) = self.payment_request_id {
                AuthenticatedSenderWithPaymentRequestIdMemo::new(
                    &**hmac_signer,
                    recipient.view_public_key(),
                    &memo_context.tx_public_key.into(),
                    payment_request_id,
                )?
                .into()
            } else if let Some(payment_intent_id) = self.payment_intent_id {
                AuthenticatedSenderWithPaymentIntentIdMemo::new(
                    &**hmac_signer,
                    recipient.view_public_key(),
                    &memo_context.tx_public_key.into(),
                    payment_intent_id,
                )?
                .into()
            } else {
                AuthenticatedSenderMemo::new(
                    &**hmac_signer,
                    recipient.view_public_key(),
                    &memo_context.tx_public_key.into(),
                )?
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

        self.total_outlay = self
            .total_outlay
            .checked_add(self.fee.value)
            .ok_or(NewMemoError::LimitsExceeded("total_outlay"))?;

        if self.payment_request_id.is_some() && self.payment_intent_id.is_some() {
            return Err(NewMemoError::RequestAndIntentIdSet);
        }

        if let Some(payment_request_id) = self.payment_request_id {
            match DestinationWithPaymentRequestIdMemo::new(
                self.last_recipient,
                self.total_outlay,
                self.fee.value,
                payment_request_id,
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
        } else if let Some(payment_intent_id) = self.payment_intent_id {
            match DestinationWithPaymentIntentIdMemo::new(
                self.last_recipient,
                self.total_outlay,
                self.fee.value,
                payment_intent_id,
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
        } else {
            match DestinationMemo::new(self.last_recipient, self.total_outlay, self.fee.value) {
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
    use assert_matches::assert_matches;
    use mc_account_keys::AccountKey;
    use mc_crypto_keys::RistrettoPublic;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn make_memo_for_output_fails_after_change_output() {
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let mut builder = RTHMemoBuilder::default();
        builder.enable_destination_memo();
        builder
            .make_memo_for_output(
                Amount::new(100, Mob::ID),
                &PublicAddress::default(),
                MemoContext {
                    tx_public_key: &RistrettoPublic::from_random(&mut rng),
                },
            )
            .unwrap();
        builder
            .make_memo_for_change_output(
                Amount::new(100, Mob::ID),
                &ReservedSubaddresses::from(&AccountKey::random(&mut rng)),
                MemoContext {
                    tx_public_key: &RistrettoPublic::from_random(&mut rng),
                },
            )
            .unwrap();

        assert_matches!(
            builder.make_memo_for_output(
                Amount::new(100, Mob::ID),
                &PublicAddress::default(),
                MemoContext {
                    tx_public_key: &RistrettoPublic::from_random(&mut rng),
                }
            ),
            Err(NewMemoError::OutputsAfterChange)
        );
    }
}
