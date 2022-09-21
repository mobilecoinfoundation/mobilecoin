#![no_std]
#![deny(missing_docs)]

//! This crate provides traits that either AccountKeys objects or Hardware
//! Wallets objects can implement to support signing a Tx, checking balance,
//! etc.

// FIXME
extern crate alloc;

mod error;
mod key_image_computer;
mod memo_hmac_signer;
mod ring_signer;

pub use error::Error;
pub use key_image_computer::KeyImageComputer;
pub use memo_hmac_signer::MemoHmacSigner;
pub use ring_signer::{InputSecret, OneTimeKeyDeriveData, RingSigner, SignableInputRing};

/// A trait which captures all the functionality of a set of account keys needed
/// to check ones balance and sign transactions.
///
/// This is meant to be generic over, a locally stored set of account keys, and
/// a connection to a hardware wallet.
///
/// Note: We still should add more functionality around computation of public
/// address, computation of view private key, subaddress view private key. At
/// the moment, this is difficult because public address is part of
/// mc-account-keys and this creates a circular dependency.
pub trait AbstractAccountKeys: KeyImageComputer + MemoHmacSigner + RingSigner {}
