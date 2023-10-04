// Copyright (c) 2023 The MobileCoin Foundation

//! Conversions from prost message types into common crate rust types.

mod collateral;
mod dcap_evidence;
mod enclave_report_data_contents;
mod quote3;

use alloc::string::{String, ToString};
use mc_crypto_keys::KeyError;
use mc_sgx_dcap_types::{CollateralError, Quote3Error};

#[derive(displaydoc::Display, Debug, Eq, PartialEq, Clone)]
/// Error converting from prost message to common crate rust type
pub enum ConversionError {
    /// The contents are not as expected: {0}
    InvalidContents(String),
    /// Other error: {0}
    Other(String),
    /**
     * The length of `{name}` does not match the expected
     * length, provided {provided}, required {required}
     */
    LengthMismatch {
        name: String,
        provided: usize,
        required: usize,
    },
    /// The key is not valid: {0}
    Key(KeyError),
    /// The field is missing: {0}
    MissingField(String),
}

impl From<KeyError> for ConversionError {
    fn from(value: KeyError) -> Self {
        Self::Key(value)
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
