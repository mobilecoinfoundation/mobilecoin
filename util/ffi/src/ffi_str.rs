// Copyright (c) 2018-2021 The MobileCoin Foundation

use super::{FfiOptRefPtr, FfiRefPtr};
use core::{fmt, marker, mem, ptr, str};
use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
};

/// A wrapper struct with a memory layout equivalent to a raw `*mut c_char`
/// pointer, meant to be used as the return type of C-compatible FFI Rust
/// function, signaling a transfer of ownership of the underlying memory of a
/// raw `CString` from Rust to the caller.
///
/// The point of this structure is to encapsulate the unsafety of
/// `CString::from_raw` within a C-compatible struct to allow for safe
/// manipulation within safe Rust code.
///
/// The caller of the above-mentioned C-FFI Rust function is responsible for
/// later calling `mc_string_free`, otherwise the underlying memory will leak.
#[derive(Debug)]
#[repr(transparent)]
pub struct FfiOwnedStr(*mut c_char);

impl FfiOwnedStr {
    #[inline]
    pub fn new(c_string: CString) -> Self {
        Self(c_string.into_raw())
    }
}

impl FfiOwnedStr {
    /// # Safety
    #[inline]
    pub unsafe fn from_raw(ptr: *mut c_char) -> Self {
        // This panic indicates a violation of a precondition to this function.
        assert!(!ptr.is_null());
        Self(ptr)
    }

    #[inline]
    pub fn into_raw(self) -> *mut c_char {
        mem::ManuallyDrop::new(self).0
    }

    #[inline]
    pub fn as_raw(&self) -> *mut c_char {
        self.0
    }
}

impl Drop for FfiOwnedStr {
    #[inline]
    fn drop(&mut self) {
        // This panic is considered a precondition violation of the struct, either from
        // misuse in unsafe Rust, in C, or a bug in the library.
        debug_assert!(!self.0.is_null());
        unsafe {
            drop(CString::from_raw(self.0));
        }
    }
}

impl From<CString> for FfiOwnedStr {
    #[inline]
    fn from(c_string: CString) -> Self {
        Self::new(c_string)
    }
}

impl<'a> From<&'a FfiOwnedStr> for FfiStr<'a> {
    #[inline]
    fn from(str: &'a FfiOwnedStr) -> Self {
        unsafe { FfiStr::from_raw(str.as_raw()) }
    }
}

impl<'a> From<&'a FfiOwnedStr> for FfiOptStr<'a> {
    #[inline]
    fn from(str: &'a FfiOwnedStr) -> Self {
        unsafe { FfiOptStr::from_raw(str.as_raw()) }
    }
}

/// This is a sibling type of `FfiOwnedStr` where the only semantic difference
/// is that this type is allowed to contain `null`.
///
/// This wrapper struct has a memory layout equivalent to a raw `*mut c_char`
/// pointer and is meant to be used as the return type of C-compatible FFI Rust
/// function.
///
/// This type signals a transfer of ownership of the underlying memory of a raw
/// `CString` from Rust to the caller, unless the contained pointer is `null`.
#[derive(Debug)]
#[repr(transparent)]
pub struct FfiOptOwnedStr(*mut c_char);

impl FfiOptOwnedStr {
    /// # Safety
    #[inline]
    pub unsafe fn from_raw(ptr: *mut c_char) -> Self {
        Self(ptr)
    }

    #[inline]
    pub fn into_raw(self) -> *mut c_char {
        mem::ManuallyDrop::new(self).0
    }

    #[inline]
    pub fn as_raw(&self) -> *mut c_char {
        self.0
    }

    #[inline]
    pub fn null() -> Self {
        Self(ptr::null_mut())
    }

    #[inline]
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }

    #[inline]
    pub fn into_option(self) -> Option<FfiOwnedStr> {
        if !self.is_null() {
            Some(unsafe { FfiOwnedStr::from_raw(self.into_raw()) })
        } else {
            None
        }
    }
}

impl Drop for FfiOptOwnedStr {
    #[inline]
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                drop(CString::from_raw(self.0));
            }

            // Not needed for correctness, but since this type is allowed to hold `null` and
            // as such code accessing this memory location will be written in a
            // way to expect `null`, so we set it here to help prevent
            // use-after-free and double freeing.
            self.0 = ptr::null_mut();
        }
    }
}

impl Default for FfiOptOwnedStr {
    #[inline]
    fn default() -> Self {
        Self::null()
    }
}

impl From<Option<FfiOwnedStr>> for FfiOptOwnedStr {
    #[inline]
    fn from(str: Option<FfiOwnedStr>) -> Self {
        match str {
            Some(str) => unsafe { Self::from_raw(str.into_raw()) },
            None => Self::null(),
        }
    }
}

impl From<FfiOwnedStr> for FfiOptOwnedStr {
    #[inline]
    fn from(str: FfiOwnedStr) -> Self {
        unsafe { Self::from_raw(str.into_raw()) }
    }
}

impl<'a> From<&'a FfiOptOwnedStr> for FfiOptStr<'a> {
    #[inline]
    fn from(str: &'a FfiOptOwnedStr) -> Self {
        unsafe { FfiOptStr::from_raw(str.as_raw()) }
    }
}

impl<'a> From<&'a FfiOptOwnedStr> for Option<FfiStr<'a>> {
    #[inline]
    fn from(str: &'a FfiOptOwnedStr) -> Self {
        if !str.is_null() {
            Some(unsafe { FfiStr::from_raw(str.as_raw()) })
        } else {
            None
        }
    }
}

/// A wrapper struct with a memory layout equivalent to a raw `*const c_char`
/// pointer to a C-style string, meant to be used as a parameter type of a
/// C-compatible FFI Rust function.
///
/// This type does *not* signal a transfer of ownership of the underlying
/// memory.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct FfiStr<'a>(FfiRefPtr<'a, c_char>, marker::PhantomData<&'a str>);

impl<'a> FfiStr<'a> {
    /// # Safety
    #[inline]
    pub unsafe fn from_raw(ptr: *const c_char) -> Self {
        Self(FfiRefPtr::from_raw(ptr), Default::default())
    }

    #[inline]
    pub fn as_raw(self) -> *const c_char {
        self.0.as_raw()
    }

    #[inline]
    pub fn as_c_str(self) -> &'a CStr {
        unsafe { std::ffi::CStr::from_ptr(self.as_raw()) }
    }

    #[inline]
    pub fn as_str(self) -> Result<&'a str, str::Utf8Error> {
        self.as_c_str().to_str()
    }

    #[inline]
    pub fn to_string_lossy(self) -> String {
        self.as_c_str().to_string_lossy().into_owned()
    }
}

impl<'a> From<&'a CStr> for FfiStr<'a> {
    #[inline]
    fn from(cstr: &'a CStr) -> Self {
        Self(
            unsafe { FfiRefPtr::from_raw(cstr.as_ptr()) },
            Default::default(),
        )
    }
}

impl<'a> fmt::Display for FfiStr<'a> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string_lossy().fmt(f)
    }
}

/// This is a sibling type of `FfiStr` where the only semantic difference is
/// that this type is allowed to contain `null`.
///
/// This wrapper struct has a memory layout equivalent to a raw `*const c_char`
/// pointer and is meant to be used as a parameter type of a C-compatible FFI
/// Rust function.
///
/// This type does *not* signal a transfer of ownership of the underlying
/// memory.
#[derive(Clone, Copy, Debug, Default)]
#[repr(transparent)]
pub struct FfiOptStr<'a>(
    FfiOptRefPtr<'a, c_char>,
    marker::PhantomData<Option<&'a str>>,
);

impl<'a> FfiOptStr<'a> {
    /// # Safety
    #[inline]
    pub unsafe fn from_raw(ptr: *const c_char) -> Self {
        Self(FfiOptRefPtr::from_raw(ptr), Default::default())
    }

    #[inline]
    pub fn as_raw(self) -> *const c_char {
        self.0.as_raw()
    }

    #[inline]
    pub fn null() -> Self {
        Self(FfiOptRefPtr::null(), Default::default())
    }

    #[inline]
    pub fn is_null(self) -> bool {
        self.0.is_null()
    }

    #[inline]
    pub fn as_c_str(self) -> Option<&'a CStr> {
        if self.is_null() {
            return None;
        }

        Some(unsafe { CStr::from_ptr(self.as_raw()) })
    }

    #[inline]
    pub fn as_str(self) -> Result<Option<&'a str>, str::Utf8Error> {
        self.as_c_str().map(CStr::to_str).transpose()
    }

    #[inline]
    pub fn to_string_lossy(self) -> Option<String> {
        self.as_c_str()
            .map(|c_str| c_str.to_string_lossy().into_owned())
    }

    #[inline]
    pub fn as_option(self) -> Option<FfiStr<'a>> {
        if !self.is_null() {
            Some(unsafe { FfiStr::from_raw(self.as_raw()) })
        } else {
            None
        }
    }
}

impl<'a> From<Option<&'a CStr>> for FfiOptStr<'a> {
    #[inline]
    fn from(cstr: Option<&'a CStr>) -> Self {
        match cstr {
            Some(cstr) => Self(
                unsafe { FfiOptRefPtr::from_raw(cstr.as_ptr()) },
                Default::default(),
            ),
            None => Self::default(),
        }
    }
}
