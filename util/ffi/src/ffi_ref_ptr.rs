// Copyright (c) 2018-2021 The MobileCoin Foundation

#![allow(clippy::should_implement_trait)]

use core::{fmt, marker, ops, ptr};
use std::panic;

#[repr(transparent)]
pub struct FfiRefPtr<'a, T: 'a + ?Sized>(*const T, marker::PhantomData<&'a T>);

impl<'a, T: ?Sized> FfiRefPtr<'a, T> {
    /// # Safety
    #[inline]
    pub unsafe fn from_raw(ptr: *const T) -> Self {
        // This panic indicates a violation of a precondition to this function.
        assert!(!ptr.is_null(), "Pointer cannot be null");
        Self(ptr, Default::default())
    }

    #[inline]
    pub fn as_raw(&self) -> *const T {
        // This panic is considered a precondition violation of the struct, either from
        // misuse in unsafe Rust, in C, or a bug in the library.
        assert!(!self.0.is_null(), "Pointer cannot be null");
        self.0
    }

    #[inline]
    pub fn as_ref(&self) -> &'a T {
        unsafe { self.0.as_ref() }
            // This panic is considered a precondition violation of the struct, either from misuse
            // in unsafe Rust, in C, or a bug in the library.
            .expect("Pointer cannot be null")
    }
}

impl<'a, T: 'a + ?Sized> ops::Deref for FfiRefPtr<'a, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'a, T: 'a + ?Sized> From<&'a T> for FfiRefPtr<'a, T> {
    #[inline]
    fn from(ptr: &'a T) -> Self {
        Self(ptr, Default::default())
    }
}

impl<'a, T: 'a + ?Sized> Copy for FfiRefPtr<'a, T> {}

impl<'a, T: 'a + ?Sized> Clone for FfiRefPtr<'a, T> {
    #[inline]
    fn clone(&self) -> Self {
        Self(self.0, Default::default())
    }
}

impl<'a, T: 'a + ?Sized> fmt::Debug for FfiRefPtr<'a, T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[repr(transparent)]
pub struct FfiMutPtr<'a, T: 'a + ?Sized>(*mut T, marker::PhantomData<&'a mut T>);

impl<'a, T: 'a + ?Sized> FfiMutPtr<'a, T> {
    /// # Safety
    #[inline]
    pub unsafe fn from_raw(ptr: *mut T) -> Self {
        // This panic indicates a violation of a precondition to this function.
        assert!(!ptr.is_null(), "Pointer cannot be null");
        Self(ptr, Default::default())
    }

    #[inline]
    pub fn as_raw(&self) -> *mut T {
        // This panic is considered a precondition violation, either from misuse in
        // unsafe Rust, in C, or a bug in the library.
        assert!(!self.0.is_null(), "Pointer cannot be null");
        self.0
    }

    #[inline]
    pub fn as_ref(&self) -> &'a T {
        unsafe { self.0.as_ref() }
            // This panic is considered a precondition violation of the struct, either from misuse
            // in unsafe Rust, in C, or a bug in the library.
            .expect("Pointer cannot be null")
    }

    #[inline]
    pub fn as_mut(&mut self) -> &'a mut T {
        unsafe { self.0.as_mut() }
            // This panic is considered a precondition violation of the struct, either from misuse
            // in unsafe Rust, in C, or a bug in the library.
            .expect("Pointer cannot be null")
    }

    #[inline]
    pub fn into_mut(mut self) -> &'a mut T {
        self.as_mut()
    }
}

impl<'a, T: 'a + ?Sized> ops::Deref for FfiMutPtr<'a, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'a, T: 'a + ?Sized> ops::DerefMut for FfiMutPtr<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl<'a, T: 'a + ?Sized> From<&'a mut T> for FfiMutPtr<'a, T> {
    #[inline]
    fn from(ptr: &'a mut T) -> Self {
        Self(ptr, Default::default())
    }
}

impl<'a, T: 'a + ?Sized> fmt::Debug for FfiMutPtr<'a, T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<'a, T: 'a + panic::RefUnwindSafe + ?Sized> panic::UnwindSafe for FfiMutPtr<'a, T> {}

#[repr(transparent)]
pub struct FfiOptRefPtr<'a, T: 'a + ?Sized>(*const T, marker::PhantomData<&'a T>);

impl<'a, T: 'a + ?Sized> FfiOptRefPtr<'a, T> {
    /// # Safety
    #[inline]
    pub unsafe fn from_raw(ptr: *const T) -> Self {
        Self(ptr, Default::default())
    }

    #[inline]
    pub fn as_raw(&self) -> *const T {
        self.0
    }

    #[inline]
    pub fn is_null(self) -> bool {
        self.0.is_null()
    }

    #[inline]
    pub fn as_ref(&self) -> Option<&'a T> {
        unsafe { self.0.as_ref() }
    }

    #[inline]
    pub fn as_option(&self) -> Option<FfiRefPtr<'a, T>> {
        if !self.is_null() {
            Some(unsafe { FfiRefPtr::from_raw(self.as_raw()) })
        } else {
            None
        }
    }
}

impl<'a, T: 'a> FfiOptRefPtr<'a, T> {
    #[inline]
    pub fn null() -> Self {
        Self(ptr::null_mut(), Default::default())
    }
}

impl<'a, T: 'a> Default for FfiOptRefPtr<'a, T> {
    #[inline]
    fn default() -> Self {
        Self::null()
    }
}

impl<'a, T: 'a + ?Sized> From<&'a T> for FfiOptRefPtr<'a, T> {
    #[inline]
    fn from(ptr: &'a T) -> Self {
        Self(ptr, Default::default())
    }
}

impl<'a, T: 'a> From<Option<&'a T>> for FfiOptRefPtr<'a, T> {
    #[inline]
    fn from(ptr: Option<&'a T>) -> Self {
        match ptr {
            Some(t) => t.into(),
            None => Self::null(),
        }
    }
}

impl<'a, T: 'a> From<FfiRefPtr<'a, T>> for FfiOptRefPtr<'a, T> {
    #[inline]
    fn from(ptr: FfiRefPtr<'a, T>) -> Self {
        unsafe { Self::from_raw(ptr.as_raw()) }
    }
}

impl<'a, T: 'a + ?Sized> Copy for FfiOptRefPtr<'a, T> {}

impl<'a, T: 'a + ?Sized> Clone for FfiOptRefPtr<'a, T> {
    #[inline]
    fn clone(&self) -> Self {
        Self(self.0, Default::default())
    }
}

impl<'a, T: 'a + ?Sized> fmt::Debug for FfiOptRefPtr<'a, T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[repr(transparent)]
pub struct FfiOptMutPtr<'a, T: 'a + ?Sized>(*mut T, marker::PhantomData<&'a mut T>);

impl<'a, T: 'a + ?Sized> FfiOptMutPtr<'a, T> {
    /// # Safety
    #[inline]
    pub unsafe fn from_raw(ptr: *mut T) -> Self {
        Self(ptr, Default::default())
    }

    #[inline]
    pub fn as_raw(&self) -> *mut T {
        self.0
    }

    #[inline]
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }

    #[inline]
    pub fn as_ref(&self) -> Option<&'a T> {
        unsafe { self.0.as_ref() }
    }

    #[inline]
    pub fn as_mut(&mut self) -> Option<&'a mut T> {
        unsafe { self.0.as_mut() }
    }

    #[inline]
    pub fn into_mut(mut self) -> Option<&'a mut T> {
        self.as_mut()
    }

    #[inline]
    pub fn into_option(self) -> Option<FfiMutPtr<'a, T>> {
        if !self.is_null() {
            Some(unsafe { FfiMutPtr::from_raw(self.as_raw()) })
        } else {
            None
        }
    }
}

impl<'a, T: 'a> FfiOptMutPtr<'a, T> {
    #[inline]
    pub fn null() -> Self {
        Self(ptr::null_mut(), Default::default())
    }
}

impl<'a, T: 'a> Default for FfiOptMutPtr<'a, T> {
    #[inline]
    fn default() -> Self {
        Self::null()
    }
}

impl<'a, T: 'a + ?Sized> From<&'a mut T> for FfiOptMutPtr<'a, T> {
    #[inline]
    fn from(ptr: &'a mut T) -> Self {
        Self(ptr, Default::default())
    }
}

impl<'a, T: 'a> From<Option<&'a mut T>> for FfiOptMutPtr<'a, T> {
    #[inline]
    fn from(ptr: Option<&'a mut T>) -> Self {
        match ptr {
            Some(t) => t.into(),
            None => Self::null(),
        }
    }
}

impl<'a, T: 'a> From<FfiMutPtr<'a, T>> for FfiOptMutPtr<'a, T> {
    #[inline]
    fn from(ptr: FfiMutPtr<'a, T>) -> Self {
        unsafe { Self::from_raw(ptr.as_raw()) }
    }
}

impl<'a, T: 'a + ?Sized> fmt::Debug for FfiOptMutPtr<'a, T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<'a, T: 'a + panic::RefUnwindSafe + ?Sized> panic::UnwindSafe for FfiOptMutPtr<'a, T> {}
