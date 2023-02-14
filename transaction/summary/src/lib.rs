// Copyright (c) 2018-2023 The MobileCoin Foundation

// Copyright (c) 2018-2022 The MobileCoin Foundation

#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

extern crate alloc;

#[cfg(feature = "mc-account-keys")]
mod data;
mod error;
mod report;
mod verifier;

#[cfg(feature = "mc-account-keys")]
pub use data::{verify_tx_summary, TxOutSummaryUnblindingData, TxSummaryUnblindingData};

pub use error::Error;
pub use report::{TransactionEntity, TxSummaryUnblindingReport};
pub use verifier::TxSummaryStreamingVerifierCtx;
