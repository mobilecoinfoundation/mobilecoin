// Copyright (c) 2018-2021 The MobileCoin Foundation

use super::{FfiTryFrom, FromFfi};
use crate::LibMcError;
use core::{convert::TryFrom, ffi::c_void};
use mc_crypto_rand::McRng;
use mc_util_ffi::FfiOptMutPtr;
use rand_core::{CryptoRng, RngCore};

#[repr(C)]
pub struct McRngCallback<'a> {
    pub rng: FfiCallbackRng,
    pub context: FfiOptMutPtr<'a, c_void>,
}

impl<'a, 'b> FromFfi<FfiOptMutPtr<'a, McRngCallback<'b>>> for SdkRng<'a, 'b> {
    #[inline]
    fn from_ffi(src: FfiOptMutPtr<'a, McRngCallback<'b>>) -> Self {
        if let Some(callback) = src.into_mut() {
            SdkRng::CallbackRng(CallbackRng(callback.rng.0, &mut callback.context))
        } else {
            SdkRng::McRng(McRng::default())
        }
    }
}

impl<'a> FfiTryFrom<u64> for i64 {
    type Error = LibMcError;

    fn ffi_try_from(src: u64) -> Result<Self, LibMcError> {
        i64::try_from(src).map_err(|err| {
            LibMcError::InvalidOutput(format!("Overflow converting to i64: {:?}", err))
        })
    }
}

/// Transparent wrapper around a function pointer that accepts a context
/// argument and returns a `u64`, intended for use as a parameter to FFI
/// functions so that foreign code may provide a callback for generating random
/// numbers.
///
/// This type has the exact memory layout as the C equivalent `uint64_t
/// (*)(void*)` function pointer.
///
/// `null` is not considered a valid value.
#[repr(transparent)]
pub struct FfiCallbackRng(unsafe extern "C" fn(*mut c_void) -> u64);

pub struct CallbackRng<'a, 'b>(
    unsafe extern "C" fn(*mut c_void) -> u64,
    &'a mut FfiOptMutPtr<'b, c_void>,
);

impl<'a, 'b> RngCore for CallbackRng<'a, 'b> {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        unsafe { (self.0)(self.1.as_raw()) }
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, dest)
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl<'a, 'b> CryptoRng for CallbackRng<'a, 'b> {}

pub enum SdkRng<'a, 'b> {
    CallbackRng(CallbackRng<'a, 'b>),
    McRng(McRng),
}

impl<'a, 'b> RngCore for SdkRng<'a, 'b> {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        match self {
            Self::CallbackRng(rng) => rng.next_u32(),
            Self::McRng(rng) => rng.next_u32(),
        }
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        match self {
            Self::CallbackRng(rng) => rng.next_u64(),
            Self::McRng(rng) => rng.next_u64(),
        }
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self {
            Self::CallbackRng(rng) => rng.fill_bytes(dest),
            Self::McRng(rng) => rng.fill_bytes(dest),
        }
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        match self {
            Self::CallbackRng(rng) => rng.try_fill_bytes(dest),
            Self::McRng(rng) => rng.try_fill_bytes(dest),
        }
    }
}

impl<'a, 'b> CryptoRng for SdkRng<'a, 'b> {}
