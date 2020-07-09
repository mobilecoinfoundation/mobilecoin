// Copyright (c) 2018-2020 MobileCoin Inc.

//! Blake2b with 256-bit output.
//!
//! BLAKE2b is optimized for 64-bit platforms and produces digests of any size between 1 and 64
//! bytes. This wrapper implements blake2b256, which uses the parameter `nn=32` as part of its
//! initialization vector.
//!
//! # References
//! * `[RFC 7693: The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)](https://tools.ietf.org/html/rfc7693)`

use blake2::{digest::BlockInput, VarBlake2b};
use digest::{
    generic_array::{
        typenum::{U128, U32},
        GenericArray,
    },
    FixedOutput, Input, Reset, VariableOutput,
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
        self.fixed_result()
    }
}

impl Default for Blake2b256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Input for Blake2b256 {
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.hasher.input(data);
    }
}

impl FixedOutput for Blake2b256 {
    type OutputSize = U32;

    fn fixed_result(self) -> GenericArray<u8, U32> {
        let mut result_opt: Option<GenericArray<u8, U32>> = None;
        self.hasher.variable_result(|res| {
            result_opt = GenericArray::from_exact_iter(res.iter().cloned());
        });
        result_opt.unwrap()
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
