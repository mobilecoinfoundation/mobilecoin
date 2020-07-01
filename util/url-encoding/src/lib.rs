// Copyright (c) 2018-2020 MobileCoin Inc.

//! mob:// URL support.

#![deny(missing_docs)]
#![deny(unsafe_code)]
extern crate alloc;

mod error;
mod mob_url;
mod payment_request;

pub use crate::{
    error::Error,
    mob_url::{MobUrl, UriParseError, MOB_SCHEME_INSECURE, MOB_SCHEME_SECURE},
    payment_request::PaymentRequest,
};
