// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Traits and support for common encoding types

#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod base64;
mod error;
mod hex;
mod x64;

pub use crate::{
    base64::{base64_buffer_size, base64_size, FromBase64, ToBase64},
    error::Error,
    hex::{FromHex, ToHex},
    x64::{FromX64, IntelLayout, ToX64, INTEL_U16_SIZE, INTEL_U32_SIZE, INTEL_U64_SIZE},
};
