#![no_std]
#![deny(missing_docs)]

//! This crate defines account key structures, including private account keys,
//! public addresses, view keys, and subaddresses.
//! It also defines their serialization as protobufs.

extern crate alloc;

mod account_keys;
mod domain_separators;
mod view_key;

pub use account_keys::{AccountKey, PublicAddress, DEFAULT_SUBADDRESS_INDEX};
pub use view_key::ViewKey;
