// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Blake2b with 256-bit output.
//!
//! BLAKE2b is optimized for 64-bit platforms and produces digests of any size
//! between 1 and 64 bytes. This wrapper implements blake2b256, which uses the
//! parameter `nn=32` as part of its initialization vector.
//!
//! # References
//! * `[RFC 7693: The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)](https://tools.ietf.org/html/rfc7693)`

use blake2::{
    digest::{
        generic_array::typenum::{U128, U32},
        Digest, FixedOutput, HashMarker, InvalidBufferSize, InvalidOutputSize, OutputSizeUser,
        Reset, Update, VariableOutput,
    },
    Blake2b,
};

#[derive(Clone, Debug)]
/// Blake2b with 256-bit output.
pub struct Blake2b256 {
    hasher: Blake2b<U32>,
}

impl Update for Blake2b256 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.hasher, data)
    }
}

impl OutputSizeUser for Blake2b256 {
    type OutputSize = U32;
}

impl VariableOutput for Blake2b256 {
    const MAX_OUTPUT_SIZE: usize = 0;

    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        // FIXME: LEFT OFF HERE
        let hasher = <Blake2b<U32> as VariableOutput>::new(output_size)?;
        Self { hasher }
    }

    fn output_size(&self) -> usize {
        self.hashser.output_size()
    }

    fn finalize_variable(self, out: &mut [u8]) -> Result<(), InvalidBufferSize> {
        VariableOutput::finalize_variable(&self.hasher, out)
    }
}

impl Reset for Blake2b256 {
    fn reset(&mut self) {
        Reset::reset(&mut self.hasher);
    }
}
