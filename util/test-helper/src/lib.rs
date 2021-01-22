// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Testing utilities

#[macro_use]
extern crate lazy_static;

pub use rand_core::{CryptoRng, RngCore, SeedableRng};
use rand_hc::Hc128Rng;

// re-export AccountKey and PublicAddress to save an import elsewhere
pub use mc_account_keys::{AccountKey, PublicAddress};

pub mod known_accounts;

type Seed = <RngType as SeedableRng>::Seed;

const NUM_TRIALS: usize = 3;

// Sometimes you need to have the type in scope to call trait functions
pub type RngType = Hc128Rng;

// Helper for running a unit test that requires randomness, but doing it
// seeded and deterministically
pub fn run_with_several_seeds<F: FnMut(RngType)>(mut f: F) {
    for seed in &get_seeds() {
        f(RngType::from_seed(*seed));
    }
}

pub fn run_with_one_seed<F: FnOnce(RngType)>(f: F) {
    f(get_seeded_rng());
}

// TODO(chris): Can we store the result of this function in a const somehow?
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
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";

    let output: String = (0..len)
        .map(|_| {
            let idx = (rng.next_u64() % CHARSET.len() as u64) as usize;
            char::from(CHARSET[idx])
        })
        .collect();

    output
}
