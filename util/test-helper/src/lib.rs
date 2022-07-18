// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Testing utilities

#[macro_use]
extern crate lazy_static;
use tempfile::{Builder, TempDir};

pub mod known_accounts;

pub use rand::{seq::SliceRandom, CryptoRng, Rng, RngCore, SeedableRng};
// re-export AccountKey and PublicAddress to save an import elsewhere
pub use mc_account_keys::{AccountKey, PublicAddress};

const NUM_TRIALS: usize = 3;

use rand_hc::Hc128Rng;
pub type RngType = Hc128Rng;
type Seed = <RngType as SeedableRng>::Seed;

// Helper for running a unit test that requires randomness, but doing it
// seeded and deterministically
pub fn run_with_several_seeds<F: FnMut(RngType)>(mut f: F) {
    for seed in *SEEDS {
        f(RngType::from_seed(seed));
    }
}

pub fn run_with_one_seed<F: FnOnce(RngType)>(f: F) {
    f(get_seeded_rng());
}

lazy_static! {
    static ref SEEDS: [Seed; NUM_TRIALS] = get_seeds();
}

fn get_seeds() -> [Seed; NUM_TRIALS] {
    let mut rng = get_seeded_rng();

    let mut result = [[0u8; 32]; NUM_TRIALS];
    for val in &mut result {
        rng.fill_bytes(&mut *val)
    }
    result
}

pub fn get_seeded_rng() -> RngType {
    RngType::from_seed([7u8; 32])
}

pub fn random_bytes_vec(num_bytes: usize, csprng: &mut (impl CryptoRng + RngCore)) -> Vec<u8> {
    let mut result = Vec::with_capacity(num_bytes);
    csprng.fill_bytes(&mut result);
    result
}

pub fn random_str(len: usize, csprng: &mut (impl CryptoRng + RngCore)) -> String {
    use rand::distributions::Alphanumeric;
    csprng
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

/// Get environment variable `OUT_DIR` provided by cargo.
fn out() -> String {
    env!("OUT_DIR").to_string()
}

/// Create a temporary directory in the directory specified by the
/// cargo-provided `OUT_DIR` environment variable.
///
/// # Panics
///
/// - If `OUT_DIR` doesn't exist
/// - If [`TempDir::new_in`] fails to create the directory.
pub fn tempdir() -> TempDir {
    let out = out();
    TempDir::new_in(&out)
        .unwrap_or_else(|err| panic!("Could not create temporary directory in {}: {}", out, err))
}

/// Create a temporary directory in the directory specified by the
/// cargo-provided `OUT_DIR` environment variable, using `prefix`.
///
/// # Panics
///
/// - If `OUT_DIR` doesn't exist
/// - If [`Builder::tempdir_in`] fails to create the directory.
pub fn tempdir_with_prefix(prefix: &str) -> TempDir {
    let out = out();
    Builder::new()
        .prefix(prefix)
        .tempdir_in(&out)
        .unwrap_or_else(|err| panic!("Could not create temporary directory in {}: {}", out, err))
}
