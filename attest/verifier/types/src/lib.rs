// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Data structures for remote attestation.
#![no_std]
extern crate alloc;

mod verification;

pub use crate::verification::{VerificationReport, VerificationSignature};
