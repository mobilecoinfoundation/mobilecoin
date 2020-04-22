// Copyright (c) 2018-2020 MobileCoin Inc.

//! EPID-Related SGX Types

mod basename;
mod platform_info;
mod quote;
mod quote_nonce;
mod spid;
mod update_info_bit;

pub use crate::{
    basename::{Basename, BASENAME_SIZE},
    platform_info::{PlatformInfo, PLATFORM_INFO_SIZE},
};
