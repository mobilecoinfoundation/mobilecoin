#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]

//! This crate defines account key structures, including private account keys,
//! public addresses, view keys, and subaddresses.
//! It also defines their serialization as protobufs.

extern crate alloc;

mod account_keys;
mod address_hash;
mod burn_address;
mod domain_separators;
mod error;
mod identity;

pub use crate::{
    account_keys::{AccountKey, PublicAddress, CHANGE_SUBADDRESS_INDEX, DEFAULT_SUBADDRESS_INDEX},
    address_hash::ShortAddressHash,
    burn_address::{burn_address, burn_address_view_private, BURN_ADDRESS_VIEW_PRIVATE},
    error::{Error, Result},
    identity::{RootEntropy, RootIdentity},
};
