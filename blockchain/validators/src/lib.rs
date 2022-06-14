// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Blockchain validators.

#![deny(missing_docs)]

pub mod error;
pub mod metadata;
#[cfg(test)]
pub mod test_utils;

pub use crate::{
    error::{ParseError, ValidationError},
    metadata::MetadataValidator,
};
