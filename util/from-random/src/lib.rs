// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A trait which provides a common API for types which can be initialized
//! from data provided by random number generators.

#![no_std]

use rand_core::{CryptoRng, RngCore};

/// A trait which can construct an object from a cryptographically secure
/// pseudo-random number generator.
pub trait FromRandom: Sized {
    /// Using a mutable RNG, take it's output to securely initialize the object
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> Self;
}
