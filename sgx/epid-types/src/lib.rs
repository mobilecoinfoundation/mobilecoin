// Copyright (c) 2018-2020 MobileCoin Inc.

//! EPID-Related SGX Types

#![cfg_attr(all(not(test), not(doctest)), no_std)]
#![deny(missing_docs)]

mod basename;
mod platform_info;
mod quote;
mod quote_nonce;
mod spid;
mod update_info;

pub use crate::{
    basename::{Basename, BASENAME_SIZE},
    platform_info::{PlatformInfo, PLATFORM_INFO_SIZE},
    quote_nonce::{QuoteNonce, QUOTE_NONCE_SIZE},
    spid::{ProviderId, PROVIDER_ID_SIZE},
    update_info::{UpdateInfo, UPDATE_INFO_SIZE},
};
// pub use crate::quote::{Quote, QUOTE_MIN_SIZE, QUOTE_MAX_SIZE};
