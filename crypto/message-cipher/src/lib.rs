// Copyright (c) 2018-2022 The MobileCoin Foundation

#![no_std]
extern crate alloc;

mod aes_impl;
mod traits;

pub use crate::{
    aes_impl::AeadMessageCipher,
    traits::{CipherError, MessageCipher, ProstCipherError},
};

/// AesMessageCipher is the one we expect to use
use aes_gcm::Aes256Gcm;
pub type AesMessageCipher = AeadMessageCipher<Aes256Gcm>;
