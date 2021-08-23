// Copyright 2018-2021 The MobileCoin Foundation

use crate::{common::*, LibMcError};
use bip39::{Language, Mnemonic};
use mc_account_keys::AccountKey;
use mc_account_keys_slip10::Slip10KeyGenerator;
use mc_crypto_keys::{ReprBytes, RistrettoPrivate};
use mc_util_ffi::*;

/// # Preconditions
///
/// * `mnemonic` - must be a nul-terminated C string containing valid UTF-8.
/// * `out_view_private_key` - length must be >= 32.
/// * `out_spend_private_key` - length must be >= 32.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_slip10_account_private_keys_from_mnemonic(
    mnemonic: FfiStr,
    account_index: u32,
    out_view_private_key: FfiMutPtr<McMutableBuffer>,
    out_spend_private_key: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let mnemonic = <&str>::try_from_ffi(mnemonic).expect("mnemonic is invalid");

        let mnemonic = Mnemonic::from_phrase(mnemonic, Language::English)
            .map_err(|err| LibMcError::InvalidInput(format!("Invalid mnemonic: {}", err)))?;
        let key = mnemonic.derive_slip10_key(account_index);
        let account_key = AccountKey::from(key);

        out_view_private_key
            .into_mut()
            .as_slice_mut_of_len(RistrettoPrivate::size())
            .expect("out_view_private_key length is insufficient")
            .copy_from_slice(account_key.view_private_key().as_ref());
        out_spend_private_key
            .into_mut()
            .as_slice_mut_of_len(RistrettoPrivate::size())
            .expect("out_spend_private_key length is insufficient")
            .copy_from_slice(account_key.spend_private_key().as_ref());
        Ok(())
    })
}
