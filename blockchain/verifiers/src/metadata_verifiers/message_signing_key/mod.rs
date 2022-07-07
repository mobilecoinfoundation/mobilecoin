// Copyright (c) 2018-2022 The MobileCoin Foundation

//! See [verifier].

pub mod config;
pub mod verifier;

pub use self::{
    config::{Config, MessageSigningKeyValidityMap, MessageSigningKeyValidityRecord},
    verifier::MessageSigningKeyVerifier,
};
