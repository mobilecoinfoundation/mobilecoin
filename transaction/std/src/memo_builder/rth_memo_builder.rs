// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Defines the RTHMemoBuilder.
//! (RTH is an abbrevation of Recoverable Transaction History.)
//! This MemoBuilder policy implements Recoverable Transaction History using
//! the encrypted memos, as envisioned in MCIP #XXX.

use super::{
    memo::{
        AuthenticatedSenderMemo, AuthenticatedSenderWithPaymentRequestIdMemo, DestinationMemo,
        SenderMemoCredential, UnusedMemo,
    },
    MemoBuilder,
};
use mc_account_keys::{AddressHash, PublicAddress};
use mc_crypto_keys::RistrettoPublic;
use mc_transaction_core::MemoPayload;

/// This memo builder attaches 0x0100 Authenticated Sender Memos to normal
/// outputs, and 0x0200 Destination Memos to change outputs.
///
/// Usage:
/// You should usually use this like:
///
///   let mut mb = RTHMemoBuilder::default();
///   mb.set_sender_cred(SenderMemoCredential::from(&account_key);
///   mb.enable_destination_memo();
///
/// Then use it to construct a transaction builder.
///
/// A memo builder configured this way will use 0x0100 Authenticated Sender Memo
/// on regular outputs and 0x0200 Destination Memo on change outputs.
///
/// If a payment request id is specified, then 0x0101 Authenticated Sender With
/// Payment Request Id Memo is used instead of 0x0100.
///
/// If no sender credential is provided then 0x0000 Unused will appear on
/// regular outputs.
///
/// If mb.enable_destination_memo() is not called 0x0000 Unused will appear on
/// change outputs.
///
/// When invoking the transaction builder, the change output must be created
/// last. If a normal output is created after the change output, an error will
/// occur.
///
/// If more than one normal output is created, only the last recipient's public
/// address will be recorded in the 0x0200 Destination Memo.
#[derive(Default, Clone, Debug)]
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
    last_recipient: AddressHash,
    // Tracks the total outlay so far
    total_outlay: u64,
    // Tracks the number of recipients so far
    num_recipients: u8,
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
    pub fn set_sender_cred(&mut self, cred: SenderMemoCredential) {
        self.sender_cred = Some(cred);
    }

    /// Clear the sender credential.
    pub fn clear_sender_cred(&mut self) {
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
    /// Build a memo for a normal output (to another party).
    fn make_memo_for_output(
        &mut self,
        value: u64,
        recipient: &PublicAddress,
        tx_public_key: &RistrettoPublic,
    ) -> Result<MemoPayload, String> {
        if self.wrote_destination_memo {
            return Err("Cannot make more outputs after the change output, the destination memo is already written".to_string());
        }
        self.total_outlay = self
            .total_outlay
            .checked_add(value)
            .ok_or_else(|| "Total outlay overflow".to_string())?;
        self.num_recipients = self
            .num_recipients
            .checked_add(1)
            .ok_or_else(|| "Num recipients overflow".to_string())?;
        self.last_recipient = AddressHash::from(recipient);
        Ok(if let Some(cred) = &self.sender_cred {
            if let Some(payment_request_id) = self.payment_request_id {
                AuthenticatedSenderWithPaymentRequestIdMemo::new(
                    &cred,
                    recipient.view_public_key(),
                    &tx_public_key.into(),
                    payment_request_id,
                )
                .into()
            } else {
                AuthenticatedSenderMemo::new(
                    &cred,
                    recipient.view_public_key(),
                    &tx_public_key.into(),
                )
                .into()
            }
        } else {
            UnusedMemo {}.into()
        })
    }

    /// Build a memo for a change output (to ourselves).
    fn make_memo_for_change_output(&mut self, fee: u64) -> Result<MemoPayload, String> {
        if !self.destination_memo_enabled {
            return Ok(UnusedMemo {}.into());
        }
        if self.wrote_destination_memo {
            return Err("Cannot make multiple change outputs".to_string());
        }
        self.total_outlay = self
            .total_outlay
            .checked_add(fee)
            .ok_or_else(|| "Total outlay overflow".to_string())?;
        let mut d_memo = DestinationMemo::new(self.last_recipient.clone(), self.total_outlay, fee)
            .map_err(|err| err.to_string())?;
        d_memo.set_num_recipients(self.num_recipients);
        self.wrote_destination_memo = true;
        Ok(d_memo.into())
    }
}
