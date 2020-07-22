// Copyright (c) 2018-2020 MobileCoin Inc.

//! SGX IAS types

#![cfg_attr(all(not(test), not(doctest)), no_std)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

extern crate alloc;

mod json;
mod nonce;
mod parsed;
mod pseudonym;
mod quote;
mod report;

pub use crate::{
    nonce::Nonce, parsed::ReportBody as ParsedReport, pseudonym::EpidPseudonym, quote::Quote,
    report::Report,
};
