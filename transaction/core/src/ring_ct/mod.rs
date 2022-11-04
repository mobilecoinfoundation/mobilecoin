// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin RingCT implementation

mod error;
mod generator_cache;
mod rct_bulletproofs;
mod signing_digest;

pub use self::{
    error::Error,
    generator_cache::GeneratorCache,
    rct_bulletproofs::{
        InputRing, OutputSecret, PresignedInputRing, SignatureRctBulletproofs, SignedInputRing,
        SigningData,
    },
    signing_digest::{compute_mlsag_signing_digest, ExtendedMessageDigest, MLSAGSigningDigest},
};
