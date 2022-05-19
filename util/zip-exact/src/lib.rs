// Copyright (c) 2018-2022 The MobileCoin Foundation

//! An iterator helper

#![no_std]
#![deny(missing_docs)]

use core::{
    fmt::{self, Debug, Display},
    iter::Zip,
};
use serde::{Deserialize, Serialize};

/// An alternate version of `Iterator::zip` which returns an error if the two
/// zipped iterators do not have the same length, rather than failing silently.
///
/// This is only implemented `for ExactSizeIterator`, because it significantly
/// simplifies the implementation and usage, and we don't need it for other
/// things.
pub fn zip_exact<T, U>(a: T, b: U) -> Result<Zip<T, U>, ZipExactError>
where
    T: ExactSizeIterator,
    U: ExactSizeIterator,
{
    if a.len() == b.len() {
        Ok(a.zip(b))
    } else {
        Err(ZipExactError(a.len(), b.len()))
    }
}

/// An error that occurs when zip_exact fails
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZipExactError(usize, usize);

impl Display for ZipExactError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "iterator len {0} != {1}", self.0, self.1)
    }
}
