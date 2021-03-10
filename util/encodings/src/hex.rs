// Copyright (c) 2018-2021 The MobileCoin Foundation

//! To/From Hex traits

use alloc::{string::String, vec::Vec};

/// A trait to support reading a string as hex.
pub trait FromHex: Sized {
    /// The error type used to handle parse errors
    type Error;

    /// Deserialize the given string into a new object.
    fn from_hex(s: &str) -> Result<Self, Self::Error>;
}

/// A trait to support encoding a given object as a self
pub trait ToHex {
    /// Serialize the contents of this object into the given byte slice.
    ///
    /// If the data fit in the given slice, this method should return
    /// `Ok(length_used)`. If the data does not fit, this method should
    /// return `Err(length_needed)`.
    fn to_hex(&self, dest: &mut [u8]) -> Result<usize, usize>;

    /// Serialize the contents of this object into a newly allocated string.
    ///
    /// Most implementers of this trate will not need to provide a custom
    /// implementation for this method.
    fn to_hex_owned(&self) -> String {
        let mut v = Vec::new();

        let capacity = self
            .to_hex(v.as_mut())
            .expect_err("Could not get the number of required bytes from ToHex::to_hex");
        v.resize(capacity, 0);
        let result = self.to_hex(v.as_mut()).expect("Could not fill bytes");
        v.truncate(result);
        String::from_utf8(v).expect("ToHex::to_hex returned invalid UTF-8")
    }
}
