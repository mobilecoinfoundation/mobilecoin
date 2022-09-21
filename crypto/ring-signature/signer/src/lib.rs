// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Interfaces for signing transactions

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

mod no_keys_ring_signer;
pub use no_keys_ring_signer::NoKeysRingSigner;

mod local_signer;
pub use local_signer::LocalRingSigner;

// For now, re-export these
pub use mc_abstract_account_keys::{Error, RingSigner, InputSecret, OneTimeKeyDeriveData, SignableInputRing};
