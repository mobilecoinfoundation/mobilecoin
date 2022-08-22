// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::common::*;
use mc_util_ffi::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::{convert::TryInto, sync::Mutex};

pub type McChaCha20Rng = ChaCha20Rng;

// McU128 facilitates conversion between u128 and 16 bytes of u8
pub struct McU128 {
    pub bytes: [u8; 16],
}

impl McU128 {
    pub fn from_u128(val: u128) -> McU128 {
        McU128 {
            bytes: val.to_be_bytes(),
        }
    }

    pub fn to_u128(&self) -> u128 {
        u128::from_be_bytes(self.bytes)
    }
}

impl IntoFfi<McU128> for McU128 {
    #[inline]
    fn error_value() -> McU128 {
        McU128 {
            bytes: [u8::MAX; 16],
        }
    }

    #[inline]
    fn into_ffi(self) -> McU128 {
        self
    }
}

impl_into_ffi!(FfiOwnedPtr<McU128>);
impl_into_ffi!(Mutex<McChaCha20Rng>);

/// Returns a new ChaCha20Rng instance initialized with the
/// seed value provided by the u64 long_val parameter
///
/// # Arguments
///
/// * `long_val` - an unsigned 64 bit value to use as the rng seed
///
/// # Errors
///
/// * `LibMcError::Poison`
#[no_mangle]
pub extern "C" fn mc_chacha20_rng_create_with_long(
    long_val: u64,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> FfiOptOwnedPtr<Mutex<McChaCha20Rng>> {
    ffi_boundary_with_error(out_error, || {
        Ok(Mutex::new(McChaCha20Rng::seed_from_u64(long_val)))
    })
}

/// Returns a new ChaCha20Rng instance initialized with the
/// seed value provided by the bytes data, which must be at
/// least 32 bytes (only the first 32 bytes will be used)
///
/// # Arguments
///
/// * `bytes` - 32 bytes of data to use as the rng seed
///
/// # Errors
///
/// * `LibMcError::Poison`
#[no_mangle]
pub extern "C" fn mc_chacha20_rng_create_with_bytes(
    bytes: FfiRefPtr<McBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> FfiOptOwnedPtr<Mutex<McChaCha20Rng>> {
    ffi_boundary_with_error(out_error, || {
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .expect("seed size must be 32 bytes");
        Ok(Mutex::new(McChaCha20Rng::from_seed(bytes)))
    })
}

/// Returns the current word_pos of the ChaCha20Rng instance
///
/// # Arguments
///
/// * `chacha20_rng` - must be a valid ChaCha20Rng
/// * `out_word_pos` - pointer to buffer of 128 bytes where the current
///   chacha20_rng wordpos will be returned
///
/// # Errors
///
/// * `LibMcError::Poison`
#[no_mangle]
pub extern "C" fn mc_chacha20_get_word_pos(
    chacha20_rng: FfiMutPtr<Mutex<McChaCha20Rng>>,
    out_word_pos: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) {
    ffi_boundary_with_error(out_error, || {
        let word_pos = chacha20_rng.lock()?.get_word_pos();
        let mc_u128 = McU128::from_u128(word_pos);

        let out_word_pos = out_word_pos.into_mut().as_slice_mut_of_len(16)?;

        out_word_pos.copy_from_slice(&mc_u128.bytes);

        Ok(())
    })
}

/// Sets the current word_pos of the ChaCha20Rng instance
///
/// /// # Arguments
///
/// * `chacha20_rng` - must be a valid ChaCha20Rng
/// * `out_word_pos` - pointer to buffer of 128 bytes where the current
///   chacha20_rng wordpos will be returned
///
/// # Errors
///
/// * `LibMcError::Poison`
#[no_mangle]
pub extern "C" fn mc_chacha20_set_word_pos(
    chacha20_rng: FfiMutPtr<Mutex<McChaCha20Rng>>,
    bytes: FfiRefPtr<McBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) {
    ffi_boundary_with_error(out_error, || {
        let mc_u128 = McU128 {
            bytes: bytes
                .as_slice()
                .try_into()
                .expect("word_pos length is not exaclty 16 bytes"),
        };
        let word_pos = mc_u128.to_u128();

        chacha20_rng.lock()?.set_word_pos(word_pos);

        Ok(())
    })
}

/// Returns the next random u64 value from the ChaCha20Rng
///
/// /// # Arguments
///
/// * `chacha20_rng` - must be a valid ChaCha20Rng
///
/// # Errors
///
/// * `LibMcError::Poison`
#[no_mangle]
pub extern "C" fn mc_chacha20_rng_next_long(
    chacha20_rng: FfiMutPtr<Mutex<McChaCha20Rng>>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> u64 {
    ffi_boundary_with_error(out_error, || Ok(chacha20_rng.lock()?.next_u64()))
}

/// frees the ChaCha20Rng
///
/// # Preconditions
/// 
/// * The ChaCha20Rng is no longer in use
/// 
/// # Arguments
///
/// * `chacha20_rng` - must be a valid ChaCha20Rng
///
/// * `chacha20_rng` - must be a valid ChaCha20Rng
#[no_mangle]
pub extern "C" fn mc_chacha20_rng_free(
    chacha20_rng: FfiOptOwnedPtr<Mutex<McChaCha20Rng>>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) {
    ffi_boundary_with_error(out_error, || {
        let _ = chacha20_rng;
        Ok(())
    })
}
