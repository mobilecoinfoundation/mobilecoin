// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Multi-signature implementation: A multi-signature is a protocol that allows
//! a group of signers, each possessing a distinct private/public keypair, to
//! produce a joint signature on a common message. The simplest multi-signature
//! of a message is just a set of signatures containing one signature over the
//! message from each member of the signing group. We say that a multi-signature
//! is an M-of-N threshold signature if only M valid signatures are required
//! from a signing group of size N.

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]

extern crate alloc;

mod constants;
mod multi_sig;
mod signer_set;

pub use constants::MAX_SIGNATURES;
pub use multi_sig::MultiSig;
pub use signer_set::{
    v1::SignerSetV1,
    v2::{Signer, SignerContainer, SignerEntity, SignerSetV2},
};
