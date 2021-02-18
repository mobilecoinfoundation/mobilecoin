// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]
extern crate alloc;

mod aes_impl;
mod traits;

pub use aes_impl::*;
pub use traits::*;

/// AesMessageCipher is the one we expect to use
use aes_gcm::Aes256Gcm;
pub type AesMessageCipher = AeadMessageCipher<Aes256Gcm>;
