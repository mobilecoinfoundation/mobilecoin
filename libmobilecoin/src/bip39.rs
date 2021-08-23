// Copyright 2018-2021 The MobileCoin Foundation

use crate::{common::*, LibMcError};
use bip39::{Language, Mnemonic};
use libc::ssize_t;
use mc_util_ffi::*;

/// # Preconditions
///
/// * `entropy` - length must be a multiple of 4 and between 16 and 32,
///   inclusive, in bytes.
#[no_mangle]
pub extern "C" fn mc_bip39_mnemonic_from_entropy(entropy: FfiRefPtr<McBuffer>) -> FfiOptOwnedStr {
    ffi_boundary(|| {
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English)
            .expect("entropy could not be converted to a mnemonic");
        FfiOwnedStr::ffi_try_from(mnemonic.to_string())
            .expect("mnemonic could not be converted to a C string")
    })
}

/// # Preconditions
///
/// * `mnemonic` - must be a nul-terminated C string containing valid UTF-8.
/// * `out_entropy` - must be null or else length must be >= `entropy.len`.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_bip39_entropy_from_mnemonic(
    mnemonic: FfiStr,
    out_entropy: FfiOptMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> ssize_t {
    ffi_boundary_with_error(out_error, || {
        let mnemonic = <&str>::try_from_ffi(mnemonic).expect("mnemonic is invalid");

        let mnemonic = Mnemonic::from_phrase(mnemonic, Language::English)
            .map_err(|err| LibMcError::InvalidInput(format!("Invalid mnemonic: {}", err)))?;
        let entropy = mnemonic.entropy();

        if let Some(out_entropy) = out_entropy.into_option() {
            let out_entropy = out_entropy
                .into_mut()
                .as_slice_mut_of_len(entropy.len())
                .expect("out_entropy length is insufficient");
            out_entropy.copy_from_slice(&entropy);
        }
        Ok(ssize_t::ffi_try_from(entropy.len())
            .expect("entropy.len() could not be converted to ssize_t"))
    })
}

/// # Preconditions
///
/// * `prefix` - must be a nul-terminated C string containing valid UTF-8.
#[no_mangle]
pub extern "C" fn mc_bip39_words_by_prefix(prefix: FfiStr) -> FfiOptOwnedStr {
    ffi_boundary(|| {
        let prefix = <&str>::try_from_ffi(prefix).expect("prefix is invalid");
        let words = Language::English.wordlist().get_words_by_prefix(prefix);
        let joined_words = words.join(",");
        FfiOwnedStr::ffi_try_from(joined_words)
            .expect("joined_words could not be converted to a C string")
    })
}
