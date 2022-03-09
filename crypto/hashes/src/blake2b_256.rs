// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Blake2b with 256-bit output.
//!
//! BLAKE2b is optimized for 64-bit platforms and produces digests of any size
//! between 1 and 64 bytes. This wrapper implements blake2b256, which uses the
//! parameter `nn=32` as part of its initialization vector.
//!
//! # References
//! * `[RFC 7693: The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)](https://tools.ietf.org/html/rfc7693)`

use blake2::Blake2b;
use digest::generic_array::typenum::U32;

/// Blake2b with 256-bit output.
pub type Blake2b256 = Blake2b<U32>;
