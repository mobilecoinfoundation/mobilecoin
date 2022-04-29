#![no_std]

use core::{
    cmp::{self, Ordering::Equal},
    fmt::{self, Debug, Display},
    iter::{Fuse, FusedIterator},
};

// A variation on ZipLongest originally written by SimonSapin,
// and dedicated to itertools https://github.com/rust-lang/rust/pull/19283
//
// This version iterates two other iterators simultaneously, but returns an
// error if they do not have the same length, rather than failing silently.

/// An iterator which iterates two other iterators simultaneously
///
/// This iterator is *fused*.
///
/// See [`.zip_exact()`](crate::mc-util-zip-exact::zip_exact) for more
/// information.
#[derive(Clone, Debug)]
#[must_use = "iterator adaptors are lazy and do nothing unless consumed"]
pub struct ZipExact<T, U> {
    a: Fuse<T>,
    b: Fuse<U>,
}

/// Create a new `ZipExact` iterator.
///
/// This iterator takes two iterators and returns a pair which is the next item
/// from both iterators. It returns None if both iterators are exhausted.
/// It returns a ZipExactError if one iterator becomes exhausted before the
/// other.
pub fn zip_exact<T, U>(a: T, b: U) -> ZipExact<T, U>
where
    T: Iterator,
    U: Iterator,
{
    ZipExact {
        a: a.fuse(),
        b: b.fuse(),
    }
}

impl<T, U> Iterator for ZipExact<T, U>
where
    T: Iterator,
    U: Iterator,
{
    type Item = Result<(T::Item, U::Item), ZipExactError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match (self.a.next(), self.b.next()) {
            (None, None) => None,
            (Some(a), Some(b)) => Some(Ok((a, b))),
            _ => Some(Err(ZipExactError {})),
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let (a_lower, a_upper) = self.a.size_hint();
        let (b_lower, b_upper) = self.b.size_hint();
        let lower = cmp::min(a_lower, b_lower);
        let upper = match (a_upper, b_upper) {
            (Some(u1), Some(u2)) => Some(cmp::min(u1, u2)),
            _ => a_upper.or(b_upper),
        };
        (lower, upper)
    }
}

impl<T, U> DoubleEndedIterator for ZipExact<T, U>
where
    T: DoubleEndedIterator + ExactSizeIterator,
    U: DoubleEndedIterator + ExactSizeIterator,
{
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        match self.a.len().cmp(&self.b.len()) {
            Equal => match (self.a.next_back(), self.b.next_back()) {
                (None, None) => None,
                (Some(a), Some(b)) => Some(Ok((a, b))),
                // These can only happen if .len() is inconsistent with .next_back()
                _ => Some(Err(ZipExactError {})),
            },
            _ => Some(Err(ZipExactError {})),
        }
    }
}

impl<T, U> ExactSizeIterator for ZipExact<T, U>
where
    T: ExactSizeIterator,
    U: ExactSizeIterator,
{
}

impl<T, U> FusedIterator for ZipExact<T, U>
where
    T: Iterator,
    U: Iterator,
{
}

#[derive(Copy, Clone, Default, Debug)]
pub struct ZipExactError {}

impl Display for ZipExactError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "ZipExactError")
    }
}
