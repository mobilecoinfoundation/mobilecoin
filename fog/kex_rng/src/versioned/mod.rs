// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{BufferedRng, Error, KexRng, KexRngCore, KexRngPubkey, NewFromKex, StoredRng};
use alloc::vec::Vec;
use core::convert::TryFrom;
use mc_crypto_keys::{Kex, Ristretto};
use rand_core::{CryptoRng, RngCore};

#[macro_use]
pub mod macros;

mod kexrng20201124;
pub use kexrng20201124::KexRng20201124;

mod buffered;
pub use buffered::BufferedKexRng;

/// A type alias reflecting the latest-released version
pub type LatestKexRngCore = KexRng20201124;

impl_multiversion_kex_rng_enum!(
    VersionedKexRng,
    kex: Ristretto,
    default: V0 => KexRng20201124,
    V0 => KexRng20201124,
);
