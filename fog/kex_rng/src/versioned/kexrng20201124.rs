// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::KexRngCore;
use blake2::{digest::generic_array, Blake2b, Digest};
use generic_array::{
    sequence::Split,
    typenum::{U16, U32},
    GenericArray,
};
use mc_crypto_keys::Ristretto;

type Output = GenericArray<u8, U16>;

/// An implementation of KexRngCore based on Blake2b hash function.
/// See README for discusison.
#[derive(Clone)]
pub struct KexRng20201124;

impl KexRngCore<Ristretto> for KexRng20201124 {
    type OutputSize = U16;

    const VERSION_ID: u32 = 0;

    fn prf(secret: &GenericArray<u8, U32>, counter: &u64) -> Output {
        let mut hasher = Blake2b::new();
        hasher.update(b"20201124");
        hasher.update(secret.as_slice());
        hasher.update(counter.to_le_bytes());
        let result = hasher.finalize();
        let (output, _): (Output, _) = result.split();
        output
    }
}
