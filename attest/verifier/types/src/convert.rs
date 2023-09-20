// Copyright (c) 2023 The MobileCoin Foundation

//! Conversions from prost message types into common crate rust types.

mod collateral;
mod quote3;

use ::prost::DecodeError;
use alloc::string::{String, ToString};
use mc_sgx_dcap_types::{CollateralError, Quote3Error};

#[derive(displaydoc::Display, Debug, Eq, PartialEq, Clone)]
/// Error converting from prost message to common crate rust type
pub enum ConversionError {
    /// The contents are not as expected: {0}
    InvalidContents(String),
    /// Other error: {0}
    Other(String),
}

impl From<DecodeError> for ConversionError {
    fn from(value: DecodeError) -> Self {
        Self::InvalidContents(value.to_string())
    }
}

impl From<Quote3Error> for ConversionError {
    fn from(value: Quote3Error) -> Self {
        Self::InvalidContents(value.to_string())
    }
}

impl From<CollateralError> for ConversionError {
    fn from(value: CollateralError) -> Self {
        Self::InvalidContents(value.to_string())
    }
}

impl From<x509_cert::der::Error> for ConversionError {
    fn from(value: x509_cert::der::Error) -> Self {
        Self::InvalidContents(value.to_string())
    }
}
