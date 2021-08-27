// Copyright (c) 2018-2021 The MobileCoin Foundation

use core::{mem, ops, ptr};

/// `FfiOwnedPtr` is a wrapper around an "owned" pointer which allows
/// manipulation in safe Rust. This type has a memory layout exactly equivalent
/// to `*mut T` and is intended for use in C FFI Rust functions for both return
/// types and parameter types.
///
/// `FfiOwnedPtr` is not allowed to be `null` in safe Rust, but `null` isn't
/// considered a forbidden (a.k.a niche) value, unlike `core::ptr::NonNull`.
/// This means that there are no forbidden values that the caller could pass
/// that would cause undefined behavior, which allows us to check for `null` and
/// panic instead.
///
/// The inner value of `FfiOwnedPtr` is a "raw" pointer to a `Box`, created
/// using `Box::into_raw`. `FfiOwnedPtr` still implements the `Drop` trait, but
/// it stores it's inner value as a "raw" pointer so that it can be safely
/// transferred across the C FFI boundary.
#[derive(Debug)]
#[repr(transparent)]
pub struct FfiOwnedPtr<T: ?Sized>(*mut T);

impl<T> FfiOwnedPtr<T> {
    #[inline]
    pub fn new(t: T) -> Self {
        Self(Box::into_raw(Box::new(t)))
    }
}

impl<T: ?Sized> FfiOwnedPtr<T> {
    /// # Safety
    #[inline]
    pub unsafe fn from_raw(ptr: *mut T) -> Self {
        // This panic indicates a violation of a precondition to this function.
        assert!(!ptr.is_null(), "Pointer cannot be null");
        Self(ptr)
    }

    #[inline]
    pub fn into_raw(self) -> *mut T {
        mem::ManuallyDrop::new(self).0
    }

    #[inline]
    pub fn as_raw(&self) -> *mut T {
        self.0
    }
}

impl<T: ?Sized> Drop for FfiOwnedPtr<T> {
    #[inline]
    fn drop(&mut self) {
        // This panic is considered a precondition violation of the struct, either from
        // misuse in unsafe Rust, in C, or a bug in the library.
        debug_assert!(!self.0.is_null());
        unsafe {
            Box::from_raw(self.0);
        }
    }
}

impl<T: ?Sized> AsRef<T> for FfiOwnedPtr<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        unsafe { self.0.as_ref() }
            // This panic is considered a precondition violation of the struct, either from misuse
            // in unsafe Rust, in C, or a bug in the library.
            .expect("Pointer cannot be null")
    }
}

impl<T: ?Sized> AsMut<T> for FfiOwnedPtr<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        unsafe { self.0.as_mut() }
            // This panic is considered a precondition violation of the struct, either from misuse
            // in unsafe Rust, in C, or a bug in the library.
            .expect("Pointer cannot be null")
    }
}

impl<T: ?Sized> ops::Deref for FfiOwnedPtr<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T: ?Sized> ops::DerefMut for FfiOwnedPtr<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

unsafe impl<T: Send + ?Sized> Send for FfiOwnedPtr<T> {}
unsafe impl<T: Send + Sync + ?Sized> Sync for FfiOwnedPtr<T> {}

/// `FfiOptOwnedPtr` is exactly the same as `FfiOwnedPtr` except that `null` is
/// considered a valid value. It has the exact same memory layout as
/// `FfiOwnedPtr`.
#[derive(Debug)]
#[repr(transparent)]
pub struct FfiOptOwnedPtr<T: ?Sized>(*mut T);

impl<T> FfiOptOwnedPtr<T> {
    #[inline]
    pub fn new(t: Option<T>) -> Self {
        match t {
            Some(t) => Self(Box::into_raw(Box::new(t))),
            None => Self::null(),
        }
    }

    #[inline]
    pub fn null() -> Self {
        Self(ptr::null_mut())
    }
}

impl<T: ?Sized> FfiOptOwnedPtr<T> {
    /// # Safety
    #[inline]
    pub unsafe fn from_raw(ptr: *mut T) -> Self {
        Self(ptr)
    }

    #[inline]
    pub fn into_raw(self) -> *mut T {
        mem::ManuallyDrop::new(self).0
    }

    #[inline]
    pub fn as_raw(&self) -> *mut T {
        self.0
    }

    #[inline]
    pub fn as_ref(&self) -> Option<&T> {
        unsafe { self.0.as_ref() }
    }

    #[inline]
    pub fn as_mut(&mut self) -> Option<&mut T> {
        unsafe { self.0.as_mut() }
    }

    #[inline]
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }

    #[inline]
    pub fn into_option(self) -> Option<FfiOwnedPtr<T>> {
        if !self.is_null() {
            Some(unsafe { FfiOwnedPtr::from_raw(self.into_raw()) })
        } else {
            None
        }
    }
}

impl<T> Default for FfiOptOwnedPtr<T> {
    #[inline]
    fn default() -> Self {
        Self::null()
    }
}

impl<T: ?Sized> From<FfiOwnedPtr<T>> for FfiOptOwnedPtr<T> {
    #[inline]
    fn from(ptr: FfiOwnedPtr<T>) -> Self {
        unsafe { Self::from_raw(ptr.into_raw()) }
    }
}

impl<T: ?Sized> Drop for FfiOptOwnedPtr<T> {
    #[inline]
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                Box::from_raw(self.0);
            }
        }
    }
}

unsafe impl<T: Send + ?Sized> Send for FfiOptOwnedPtr<T> {}
unsafe impl<T: Send + Sync + ?Sized> Sync for FfiOptOwnedPtr<T> {}
