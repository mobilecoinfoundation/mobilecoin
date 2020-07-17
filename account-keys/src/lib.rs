#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_code)]

//! This crate defines account key structures, including private account keys,
//! public addresses, view keys, and subaddresses.
//! It also defines their serialization as protobufs.

extern crate alloc;

mod account_keys;
mod domain_separators;
mod entropy_check;
mod identity;
mod view_key;

pub use account_keys::{AccountKey, PublicAddress, DEFAULT_SUBADDRESS_INDEX};
pub use domain_separators::FOG_AUTHORITY_SIGNATURE_TAG;
pub use entropy_check::{check_root_entropy, RootEntropyProblem};
pub use identity::RootIdentity;
pub use view_key::ViewKey;
