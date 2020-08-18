//! Definition of CtAeadDecrypt trait and an implementation for AesGcm object.

#![no_std]

extern crate alloc;

// Re-export the versions of traits and objects from our dependencies
pub use aes_gcm;

mod aes_impl;

mod traits;
pub use traits::CtAeadDecrypt;
