// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A memo handler object which processes memos, for use in integration tests

use displaydoc::Display;
use mc_account_keys::{AccountKey, PublicAddress, ShortAddressHash, CHANGE_SUBADDRESS_INDEX};
use mc_common::logger::{log, Logger};
use mc_crypto_keys::{KeyError, RistrettoPublic};
use mc_transaction_core::{get_tx_out_shared_secret, subaddress_matches_tx_out, tx::TxOut};
use mc_transaction_std::{MemoDecodingError, MemoType};
use std::{collections::HashMap, convert::TryFrom};

/// A handler object that holds a contacts list and tries to recieve and
/// authenticate memos. It provides the "get_last_memo" function which can be
/// used to check what the last memo recieved was, and if there were validation
/// errors.
///
/// This is useful for test code.
#[derive(Debug, Clone)]
pub struct MemoHandler {
    contacts: HashMap<ShortAddressHash, PublicAddress>,
    last_memo: Result<Option<MemoType>, MemoHandlerError>,
    logger: Logger,
}

impl MemoHandler {
    /// Make a new memo handler with a given set of contacts
    pub fn new(address_book: Vec<PublicAddress>, logger: Logger) -> Self {
        Self {
            contacts: address_book
                .into_iter()
                .map(|addr| (ShortAddressHash::from(&addr), addr))
                .collect(),
            last_memo: Ok(None),
            logger,
        }
    }

    /// Get the last memo, or memo handler error, that was processed, if any
    pub fn get_last_memo(&self) -> &Result<Option<MemoType>, MemoHandlerError> {
        &self.last_memo
    }

    /// Handle a memo
    pub fn handle_memo(&mut self, tx_out: &TxOut, account_key: &AccountKey) {
        self.last_memo = self.handle_memo_helper(tx_out, account_key);
    }

    // Helper for handle_memo function. The result of this gets assigned to
    // self.last_memo, and so we can use rust ? syntax in this code.
    fn handle_memo_helper(
        &mut self,
        tx_out: &TxOut,
        account_key: &AccountKey,
    ) -> Result<Option<MemoType>, MemoHandlerError> {
        let decompressed_tx_pub = RistrettoPublic::try_from(&tx_out.public_key)?;
        let shared_secret =
            get_tx_out_shared_secret(account_key.view_private_key(), &decompressed_tx_pub);

        let memo_payload = tx_out.decrypt_memo(&shared_secret);

        let memo_type = MemoType::try_from(&memo_payload)?;
        log::info!(self.logger, "Obtained a memo: {:?}", memo_type);
        match memo_type.clone() {
            MemoType::Unused(_) => Ok(None),
            MemoType::AuthenticatedSender(memo) => {
                if let Some(addr) = self.contacts.get(&memo.sender_address_hash()) {
                    if bool::from(memo.validate(
                        addr,
                        &account_key.default_subaddress_view_private(),
                        &tx_out.public_key,
                    )) {
                        Ok(Some(memo_type))
                    } else {
                        Err(MemoHandlerError::FailedHmacValidation)
                    }
                } else {
                    Err(MemoHandlerError::UnknownSender)
                }
            }
            MemoType::AuthenticatedSenderWithPaymentRequestId(memo) => {
                if let Some(addr) = self.contacts.get(&memo.sender_address_hash()) {
                    if bool::from(memo.validate(
                        addr,
                        &account_key.default_subaddress_view_private(),
                        &tx_out.public_key,
                    )) {
                        Ok(Some(memo_type))
                    } else {
                        Err(MemoHandlerError::FailedHmacValidation)
                    }
                } else {
                    Err(MemoHandlerError::UnknownSender)
                }
            }
            MemoType::Destination(_) => {
                if subaddress_matches_tx_out(account_key, CHANGE_SUBADDRESS_INDEX, tx_out)? {
                    Ok(Some(memo_type))
                } else {
                    Err(MemoHandlerError::FailedSubaddressValidation)
                }
            }
        }
    }
}

/// An error that occurs when the memo handler can't process or validate a memo
#[derive(Display, Debug, Clone)]
pub enum MemoHandlerError {
    /// Unknown Sender
    UnknownSender,

    /// Failed Hmac validation
    FailedHmacValidation,

    /// Failed subaddress validation
    FailedSubaddressValidation,

    /// Key: {0}
    Key(KeyError),

    /// Memo Decoding: {0}
    MemoDecode(MemoDecodingError),
}

impl From<KeyError> for MemoHandlerError {
    fn from(src: KeyError) -> Self {
        Self::Key(src)
    }
}

impl From<MemoDecodingError> for MemoHandlerError {
    fn from(src: MemoDecodingError) -> Self {
        Self::MemoDecode(src)
    }
}
