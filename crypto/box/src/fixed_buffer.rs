// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Fixed-length buffer, useful for operating on a portion of an underlying
//! buffer.

use crate::aead::{Buffer, Error};

/// The rust aead crate is organized around a Buffer trait which abstracts
/// commonalities of alloc::vec::Vec and heapless::Vec which are useful for
/// aead abstractions.
///
/// The needed functionalities are:
/// - Getting the bytes that have been written as a &mut [u8] (or &[u8])
/// - Extending the buffer (which is allowed to fail)
/// - Truncating the buffer
///
/// A drawback of heapless is that it is strictly an "owning" data-structure,
/// it doesn't have light-weight "views" or "reference" types.
///
/// This provides a zero-overhead abstraction over &mut [u8] which does this,
/// so that applications can easily use the aead trait to encrypt into e.g.
/// [u8; 128] without using vec, making allocations, or using heapless, which
/// might commit them to storing extra counters in their structures.
///
/// This represents a view of a fixed capacity buffer, where len() indicates
/// how many bytes, from the beginning of the buffer, have been "used".
///
/// It is expected that this type will be used to wrap e.g. [u8;128] briefly
/// in order to interact with interfaces like Aead, and then discarded.
pub struct FixedBuffer<'a> {
    buf: &'a mut [u8],
    length: usize,
}

impl<'a> AsRef<[u8]> for FixedBuffer<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.length]
    }
}

impl<'a> AsMut<[u8]> for FixedBuffer<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.length]
    }
}

impl<'a> Buffer for FixedBuffer<'a> {
    fn len(&self) -> usize {
        self.length
    }
    fn is_empty(&self) -> bool {
        self.length == 0
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), Error> {
        if other.len() > self.buf.len() - self.length {
            return Err(Error);
        }
        self.buf[self.length..self.length + other.len()].copy_from_slice(other);
        self.length += other.len();
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.length = core::cmp::min(self.length, len);
    }
}

impl<'a> FixedBuffer<'a> {
    /// Create a new FixedBuffer "view" over a mutable slice of bytes,
    /// with length set to zero, so that we will be overwriting those bytes.
    pub fn overwriting(target: &'a mut [u8]) -> Self {
        Self {
            buf: target,
            length: 0,
        }
    }

    /// Test if there is no more space to extend the buffer,
    /// i.e. we have completely exhausted the capacity.
    pub fn is_exhausted(&self) -> bool {
        self.buf.len() == self.length
    }
}

impl<'a> From<&'a mut [u8]> for FixedBuffer<'a> {
    /// Initialize a fixed buffer from a mutable slice, which is initially
    /// "exhausted", so all of the initial values of those bytes are in the
    /// buffer. This buffer can then be modified or truncated etc.
    fn from(buf: &'a mut [u8]) -> Self {
        let length = buf.len();
        Self { buf, length }
    }
}
