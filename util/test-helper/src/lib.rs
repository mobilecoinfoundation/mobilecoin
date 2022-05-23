// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Testing utilities

#[macro_use]
extern crate lazy_static;

pub mod known_accounts;

pub use rand::{CryptoRng, Rng, RngCore, SeedableRng};
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

pub fn random_str(rng: &mut RngType, len: usize) -> String {
    use rand::distributions::Alphanumeric;
    rng.sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}
