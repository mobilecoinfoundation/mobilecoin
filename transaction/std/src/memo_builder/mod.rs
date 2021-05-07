// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Defines the MemoBuilder trait, and the Default implementation
//! The memo builder for recoverable transaction history is defined in a
//! submodule.

use super::memo;
use mc_account_keys::PublicAddress;
use mc_crypto_keys::RistrettoPublic;
use mc_transaction_core::MemoPayload;

mod rth_memo_builder;
pub use rth_memo_builder::RTHMemoBuilder;

/// The MemoBuilder trait defines the API that the transaction builder uses
/// to ask the memo builder to build a memo for a particular TxOut.
///
/// The intention is that the memo builder represents a policy for the entire
/// transaction, and it is constructed and configured first. Then, it is
/// installed in the transaction builder when that is constructed.
/// This way low-level handing of memo payloads with TxOuts is not needed,
/// and just invoking the TransactionBuilder as before will do the right thing.
pub trait MemoBuilder {
    /// Build a memo for a normal output (to another party).
    fn make_memo_for_output(
        &mut self,
        value: u64,
        recipient: &PublicAddress,
        tx_public_key: &RistrettoPublic,
    ) -> Result<MemoPayload, String>;

    /// Build a memo for a change output (to ourselves).
    fn make_memo_for_change_output(&mut self, fee: u64) -> Result<MemoPayload, String>;
}

/// The default memo builder always builds UnusedMemo.
/// This is the safe and maximally private default.
#[derive(Default, Clone)]
pub struct DefaultMemoBuilder;

impl MemoBuilder for DefaultMemoBuilder {
    fn make_memo_for_output(
        &mut self,
        _value: u64,
        _recipient: &PublicAddress,
        _tx_public_key: &RistrettoPublic,
    ) -> Result<MemoPayload, String> {
        Ok(memo::UnusedMemo {}.into())
    }

    fn make_memo_for_change_output(&mut self, _fee: u64) -> Result<MemoPayload, String> {
        Ok(memo::UnusedMemo {}.into())
    }
}
