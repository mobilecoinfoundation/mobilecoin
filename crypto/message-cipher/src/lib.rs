// Copyright (c) 2018-2020 MobileCoin Inc.

#![no_std]
extern crate alloc;

mod aes_impl;
mod traits;

pub use aes_impl::*;
pub use traits::*;

/// AesMessageCipher is the one we expect to use
use aes_gcm::Aes128Gcm;
pub type AesMessageCipher = AeadMessageCipher<Aes128Gcm>;
