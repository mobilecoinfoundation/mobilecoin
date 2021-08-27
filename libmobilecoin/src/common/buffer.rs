// Copyright (c) 2018-2021 The MobileCoin Foundation

use super::{FfiTryFrom, TryFromFfi};
use crate::LibMcError;
use core::{convert::TryFrom, marker, ops, slice};
use libc::{size_t, ssize_t};
use mc_util_ffi::{FfiMutPtr, FfiRefPtr};

/// This type is meant to be used as a parameter (or field of an another
/// parameter, etc) to C-FFI functions to code written in Rust. Objects of this
/// type are typically allocated on the foreign side of the FFI boundary and are
/// passed in to Rust via an `extern fn`-style function.
///
/// The purpose of this type is to encapsulate unsafety within a type, such that
/// if this type were to be created solely in safe Rust, that it would contain
/// no unsafety. This is to say that, while this type performs unsafe operations
/// internally, in order for those unsafe operations to actually cause unsafety,
/// this type must have been created or otherwise manipulated from unsafe
/// code (typically either unsafe Rust or unsafe-by-definition foreign code).
/// Therefore, care must be taken when using this type from unsafe code (and
/// indeed it is intended to be used from unsafe code), but the same care does
/// not need to be taken in order to otherwise use it from safe code,
/// with the assumption that no preconditions were violated from unsafe code.
#[repr(C)]
pub struct McBuffer<'a> {
    buffer: FfiRefPtr<'a, u8>,
    len: size_t,
    _phantom: marker::PhantomData<&'a [u8]>,
}

impl<'a> McBuffer<'a> {
    #[inline]
    pub fn len(&self) -> size_t {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn as_slice(&self) -> &'a [u8] {
        if self.len == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(self.buffer.as_raw(), self.len) }
        }
    }

    pub fn as_slice_of_len(&self, len: usize) -> Result<&'a [u8], LibMcError> {
        if self.len < len {
            return Err(LibMcError::InvalidInput(format!(
                "buffer.len() ({}) must be >= {}",
                self.len(),
                len
            )));
        }

        Ok(&self.as_slice()[..len])
    }

    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

impl<'a> ops::Deref for McBuffer<'a> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for McBuffer<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[repr(C)]
pub struct McMutableBuffer<'a> {
    buffer: FfiMutPtr<'a, u8>,
    len: size_t,
    _phantom: marker::PhantomData<&'a [u8]>,
}

impl<'a> McMutableBuffer<'a> {
    #[inline]
    pub fn len(&self) -> size_t {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn as_slice(&self) -> &'a [u8] {
        if self.len == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(self.buffer.as_raw(), self.len) }
        }
    }

    #[inline]
    pub fn as_slice_mut(&mut self) -> &'a mut [u8] {
        if self.len == 0 {
            &mut []
        } else {
            unsafe { slice::from_raw_parts_mut(self.buffer.as_raw(), self.len) }
        }
    }

    pub fn as_slice_of_len(&self, len: usize) -> Result<&'a [u8], LibMcError> {
        if self.len < len {
            return Err(LibMcError::InvalidInput(format!(
                "buffer.len() ({}) must be >= {}",
                self.len(),
                len
            )));
        }

        Ok(&self.as_slice()[..len])
    }

    pub fn as_slice_mut_of_len(&mut self, len: usize) -> Result<&'a mut [u8], LibMcError> {
        if self.len < len {
            return Err(LibMcError::InvalidInput(format!(
                "buffer.len() ({}) must be >= {}",
                self.len(),
                len
            )));
        }

        Ok(&mut self.as_slice_mut()[..len])
    }

    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

impl<'a> ops::Deref for McMutableBuffer<'a> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<'a> ops::DerefMut for McMutableBuffer<'a> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_slice_mut()
    }
}

impl AsRef<[u8]> for McMutableBuffer<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for McMutableBuffer<'_> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

impl<'a> TryFromFfi<&McBuffer<'a>> for &'a [u8; 32] {
    type Error = LibMcError;

    #[inline]
    fn try_from_ffi(src: &McBuffer<'a>) -> Result<Self, LibMcError> {
        let src = src.as_slice_of_len(32)?;
        // SAFETY: ok to unwrap because we just checked length
        Ok(<&[u8; 32]>::try_from(src).unwrap())
    }
}

impl<'a> TryFromFfi<&McBuffer<'a>> for [u8; 32] {
    type Error = LibMcError;

    #[inline]
    fn try_from_ffi(src: &McBuffer<'a>) -> Result<Self, LibMcError> {
        Ok(*<&'a [u8; 32]>::try_from_ffi(src)?)
    }
}

impl<'a> FfiTryFrom<size_t> for ssize_t {
    type Error = LibMcError;

    fn ffi_try_from(src: size_t) -> Result<Self, LibMcError> {
        ssize_t::try_from(src).map_err(|err| {
            LibMcError::InvalidOutput(format!("Overflow converting to ssize_t: {:?}", err))
        })
    }
}
