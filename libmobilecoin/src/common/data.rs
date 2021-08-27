// Copyright (c) 2018-2021 The MobileCoin Foundation

use super::*;
use libc::ssize_t;
use mc_util_ffi::{FfiOptMutPtr, FfiOptOwnedPtr, FfiRefPtr};

pub type McData = Vec<u8>;
impl_into_ffi!(Vec<u8>);

#[no_mangle]
pub extern "C" fn mc_data_free(data: FfiOptOwnedPtr<McData>) {
    ffi_boundary(|| {
        let _ = data;
    })
}

/// # Preconditions
///
/// * `out_bytes` - must be null or else length must be >= `data.len`.
#[no_mangle]
pub extern "C" fn mc_data_get_bytes(
    data: FfiRefPtr<McData>,
    out_bytes: FfiOptMutPtr<McMutableBuffer>,
) -> ssize_t {
    ffi_boundary(|| {
        if let Some(out_bytes) = out_bytes.into_option() {
            out_bytes
                .into_mut()
                .as_slice_mut_of_len(data.len())
                .expect("out_bytes length is insufficient")
                .copy_from_slice(&data);
        }
        ssize_t::ffi_try_from(data.len()).expect("data.len could not be converted to ssize_t")
    })
}
