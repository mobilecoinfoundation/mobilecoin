// Copyright (c) 2018-2020 MobileCoin Inc.

//! EPID-Related SGX Types

#![cfg_attr(all(not(test), not(doctest)), no_std)]
#![deny(missing_docs)]

extern crate alloc;

mod basename;
mod epid_group_id;
mod platform_info;
mod quote;
mod quote_nonce;
mod quote_sign;
mod sigrl;
mod spid;
mod update_info;

pub use crate::{
    basename::{Basename, BASENAME_SIZE},
    epid_group_id::{EpidGroupId, EPID_GROUP_ID_SIZE},
    platform_info::{PlatformInfo, PLATFORM_INFO_SIZE},
    quote::{Quote, QUOTE_MIN_SIZE, QUOTE_SIGLEN_MAX},
    quote_nonce::{QuoteNonce, QUOTE_NONCE_SIZE},
    quote_sign::QuoteSign,
    sigrl::SignatureRevocationList,
    spid::{ProviderId, PROVIDER_ID_SIZE},
    update_info::{UpdateInfo, UPDATE_INFO_SIZE},
};
