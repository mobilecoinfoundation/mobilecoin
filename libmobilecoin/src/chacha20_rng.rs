use crate::common::{ffi_boundary_with_error, McBuffer, McError, McMutableBuffer};
use crate::LibMcError;
use mc_util_ffi::{FfiMutPtr, FfiOptMutPtr, FfiOptOwnedPtr, FfiRefPtr};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::{convert::TryInto, sync::Mutex};

pub type McChaCha20Rng = ChaCha20Rng;

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
/// * `LibMcError::InvalidInput`
/// * `LibMcError::Poison`
#[no_mangle]
pub extern "C" fn mc_chacha20_rng_create_with_bytes(
    bytes: FfiRefPtr<McBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> FfiOptOwnedPtr<Mutex<McChaCha20Rng>> {
    ffi_boundary_with_error(out_error, || {
        let bytes: [u8; 32] = bytes
            .as_slice_of_len(32)?
            .try_into()
            .map_err(|_| LibMcError::InvalidInput("seed bytes length must be exactly 32 bytes".to_owned()))?;
        Ok(Mutex::new(McChaCha20Rng::from_seed(bytes)))
    })
}

/// Returns the current word_pos of the ChaCha20Rng instance
///
/// # Arguments
///
/// * `chacha20_rng` - must be a valid ChaCha20Rng
/// * `out_word_pos` - pointer to buffer of 16 bytes where the current
///   chacha20_rng wordpos will be returned
///
/// # Errors
///
/// * `LibMcError::Poison`
#[no_mangle]
pub extern "C" fn mc_chacha20_rng_get_word_pos(
    chacha20_rng: FfiMutPtr<Mutex<McChaCha20Rng>>,
    out_word_pos: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let word_pos = chacha20_rng.lock()?.get_word_pos();
        let out_word_pos = out_word_pos.into_mut().as_slice_mut_of_len(16)?;
        out_word_pos.copy_from_slice(&word_pos.to_be_bytes());
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
pub extern "C" fn mc_chacha20_rng_set_word_pos(
    chacha20_rng: FfiMutPtr<Mutex<McChaCha20Rng>>,
    bytes: FfiRefPtr<McBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let bytes: [u8; 16] = bytes
            .as_slice_of_len(16)?
            .try_into()
            .map_err(|_| LibMcError::InvalidInput("bytes length must be exactly 16 bytes for word_pos".to_owned()))?;
        chacha20_rng.lock()?.set_word_pos(u128::from_be_bytes(bytes));
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
#[no_mangle]
pub extern "C" fn mc_chacha20_rng_free(
    chacha20_rng: FfiOptOwnedPtr<Mutex<McChaCha20Rng>>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let _ = chacha20_rng;
        Ok(())
    })
}
