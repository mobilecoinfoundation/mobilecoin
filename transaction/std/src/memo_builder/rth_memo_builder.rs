// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Defines the RTHMemoBuilder.
//! (RTH is an abbrevation of Recoverable Transaction History.)
//! This MemoBuilder policy implements Recoverable Transaction History using
//! the encrypted memos, as envisioned in MCIP #4.

use super::{
    memo::{
        AuthenticatedSenderMemo, AuthenticatedSenderWithPaymentRequestIdMemo, DestinationMemo,
        DestinationMemoError, SenderMemoCredential, UnusedMemo,
    },
    MemoBuilder,
};
use crate::ChangeDestination;
use mc_account_keys::{PublicAddress, ShortAddressHash};
use mc_transaction_core::{constants::MINIMUM_FEE, MemoContext, MemoPayload, NewMemoError};

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
    // The payment request id, if any
    payment_request_id: Option<u64>,
    // Whether destination memos are enabled.
    destination_memo_enabled: bool,
    // Tracks if we already wrote a destination memo, for error reporting
    wrote_destination_memo: bool,
    // Tracks the last recipient
    last_recipient: ShortAddressHash,
    // Tracks the total outlay so far
    total_outlay: u64,
    // Tracks the number of recipients so far
    num_recipients: u8,
    // Tracks the fee
    fee: u64,
}

impl Default for RTHMemoBuilder {
    fn default() -> Self {
        Self {
            sender_cred: Default::default(),
            payment_request_id: None,
            destination_memo_enabled: false,
            wrote_destination_memo: false,
            last_recipient: Default::default(),
            total_outlay: 0,
            num_recipients: 0,
            fee: MINIMUM_FEE,
        }
    }
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
    pub fn set_payment_request_id(&mut self, id: u64) {
        self.payment_request_id = Some(id);
    }

    /// Clear the payment request id.
    pub fn clear_payment_request_id(&mut self) {
        self.payment_request_id = None;
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
    fn set_fee(&mut self, fee: u64) -> Result<(), NewMemoError> {
        if self.wrote_destination_memo {
            return Err(NewMemoError::FeeAfterChange);
        }
        self.fee = fee;
        Ok(())
    }

    /// Build a memo for a normal output (to another party).
    fn make_memo_for_output(
        &mut self,
        value: u64,
        recipient: &PublicAddress,
        memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if self.wrote_destination_memo {
            return Err(NewMemoError::OutputsAfterChange);
        }
        self.total_outlay = self
            .total_outlay
            .checked_add(value)
            .ok_or(NewMemoError::LimitsExceeded("total_outlay"))?;
        self.num_recipients = self
            .num_recipients
            .checked_add(1)
            .ok_or(NewMemoError::LimitsExceeded("num_recipients"))?;
        self.last_recipient = ShortAddressHash::from(recipient);
        Ok(if let Some(cred) = &self.sender_cred {
            if let Some(payment_request_id) = self.payment_request_id {
                AuthenticatedSenderWithPaymentRequestIdMemo::new(
                    &cred,
                    recipient.view_public_key(),
                    &memo_context.tx_public_key.into(),
                    payment_request_id,
                )
                .into()
            } else {
                AuthenticatedSenderMemo::new(
                    &cred,
                    recipient.view_public_key(),
                    &memo_context.tx_public_key.into(),
                )
                .into()
            }
        } else {
            UnusedMemo {}.into()
        })
    }

    /// Build a memo for a change output (to ourselves).
    fn make_memo_for_change_output(
        &mut self,
        _value: u64,
        _change_destination: &ChangeDestination,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if !self.destination_memo_enabled {
            return Ok(UnusedMemo {}.into());
        }
        if self.wrote_destination_memo {
            return Err(NewMemoError::MultipleChangeOutputs);
        }
        self.total_outlay = self
            .total_outlay
            .checked_add(self.fee)
            .ok_or(NewMemoError::LimitsExceeded("total_outlay"))?;
        match DestinationMemo::new(self.last_recipient.clone(), self.total_outlay, self.fee) {
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
