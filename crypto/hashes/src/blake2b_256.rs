// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Blake2b with 256-bit output.
//!
//! BLAKE2b is optimized for 64-bit platforms and produces digests of any size
//! between 1 and 64 bytes. This wrapper implements blake2b256, which uses the
//! parameter `nn=32` as part of its initialization vector.
//!
//! # References
//! * `[RFC 7693: The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)](https://tools.ietf.org/html/rfc7693)`

use blake2::{digest::BlockInput, VarBlake2b};
use digest::{
    generic_array::{
        typenum::{U128, U32},
        GenericArray,
    },
    FixedOutput, FixedOutputDirty, Reset, Update, VariableOutput,
};

#[derive(Clone, Debug)]
/// Blake2b with 256-bit output.
pub struct Blake2b256 {
    hasher: VarBlake2b,
}

impl Blake2b256 {
    /// Create a new instance of this hasher.
    pub fn new() -> Self {
        Self {
            hasher: VarBlake2b::new(32).unwrap(),
        }
    }

    /// Returns the hash of inputted data.
    pub fn result(self) -> GenericArray<u8, U32> {
        self.finalize_fixed()
    }
}

impl Default for Blake2b256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Update for Blake2b256 {
    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.hasher.update(data);
    }
}

impl FixedOutputDirty for Blake2b256 {
    type OutputSize = U32;

    fn finalize_into_dirty(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        let mut result_opt: Option<GenericArray<u8, U32>> = None;
        self.hasher.finalize_variable_reset(|res| {
            result_opt = GenericArray::from_exact_iter(res.iter().cloned());
        });
        *out = result_opt.unwrap()
    }
}

impl Reset for Blake2b256 {
    fn reset(&mut self) {
        self.hasher.reset()
    }
}

impl BlockInput for Blake2b256 {
    type BlockSize = U128;
}
