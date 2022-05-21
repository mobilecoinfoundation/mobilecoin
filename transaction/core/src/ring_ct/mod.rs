// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin ring signatures

#![allow(non_snake_case)]

pub use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

mod error;
mod rct_bulletproofs;

pub use error::Error;
pub use rct_bulletproofs::*;

// TODO: Maybe don't do these re-exports
pub use mc_crypto_ring_signature::{
    CurveScalar, Error as MLSAGError, GeneratorCache, KeyImage, RingMLSAG,
};
