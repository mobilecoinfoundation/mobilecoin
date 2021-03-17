// Copyright (c) 2018-2021 The MobileCoin Foundation

//! To/From Hex traits

use alloc::{string::String, vec::Vec};
use core::cmp::max;

/// A trait to support reading a string as hex.
pub trait FromBase64: Sized {
    /// The error type used to handle parse errors
    type Error;

    /// Deserialize the given string into a new object.
    fn from_base64(s: &str) -> Result<Self, Self::Error>;
}

/// A trait to support encoding a given object as a self
pub trait ToBase64 {
    /// Serialize the contents of this object into the given byte slice.
    ///
    /// If the data fit in the given slice, this method should return
    /// `Ok(length_used)`. If the data does not fit, this method should
    /// return `Err(length_needed)`.
    fn to_base64(&self, dest: &mut [u8]) -> Result<usize, usize>;

    /// Serialize the contents of this object into a newly allocated string.
    ///
    /// Most implementers of this trate will not need to provide a custom
    /// implementation for this method.
    fn to_base64_owned(&self) -> String {
        let mut v = Vec::new();

        let capacity = self
            .to_base64(v.as_mut())
            .expect_err("Could not get the number of required bytes from ToBase64::to_base64");
        v.resize(capacity, 0);
        let result = self.to_base64(v.as_mut()).expect("Could not fill bytes");
        v.truncate(result);
        String::from_utf8(v).expect("ToBase64::to_base64 returned invalid UTF-8")
    }
}

/// Calculate the size of the buffer which [binascii::b64encode] must be given.
///
/// This will ensure at least one extra byte beyond the unpadded data length is
/// available for that function to write a (potentially) spurious padding
/// character into.
#[inline(always)]
pub fn base64_buffer_size(byte_len: usize) -> usize {
    let data_len = byte_len * 4 / 3;
    let pad_len = (4 - (data_len % 4)) % 4;
    data_len + max(pad_len, 1)
}

/// Calculate the base64 encoded size of the given number of bytes.
#[inline(always)]
pub fn base64_size(byte_len: usize) -> usize {
    let data_len = byte_len * 4 / 3;
    let pad_len = (4 - (data_len % 4)) % 4;
    data_len + pad_len
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn buffer_size() {
        const RESULTS: [usize; 13] = [1, 4, 4, 5, 8, 8, 9, 12, 12, 13, 16, 16, 17];

        for (i, result) in RESULTS.iter().enumerate() {
            assert_eq!(*result, base64_buffer_size(i));
        }
    }
}
