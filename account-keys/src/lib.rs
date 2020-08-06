#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![feature(custom_test_frameworks)]
#![test_runner(datatest::runner)]

//! This crate defines account key structures, including private account keys,
//! public addresses, view keys, and subaddresses.
//! It also defines their serialization as protobufs.

extern crate alloc;

mod account_keys;
mod domain_separators;
mod identity;
mod view_key;

pub use account_keys::{AccountKey, PublicAddress, DEFAULT_SUBADDRESS_INDEX};
pub use domain_separators::FOG_AUTHORITY_SIGNATURE_TAG;
pub use identity::{RootEntropy, RootIdentity};
pub use view_key::ViewKey;
