// Copyright (c) 2018-2021 The MobileCoin Foundation

use super::ffi_boundary;
use mc_util_ffi::{FfiOptOwnedPtr, FfiOwnedStr};
use std::{ffi::CString, os::raw::c_int};

#[repr(C)]
pub struct McError {
    error_code: c_int,
    error_description: FfiOwnedStr,
}

impl McError {
    pub fn new(error_code: c_int, error_description: String) -> Self {
        let description = CString::new(error_description)
            // This panic indicates a violation of a precondition to this function and would be
            // considered a bug in the library.
            .expect("String cannot contain nul bytes.");
        Self {
            error_code,
            error_description: description.into(),
        }
    }
}

/// All non-null owned pointers of type `McError *` that are returned from a
/// Rust FFI function to a foreign caller must call this function in order to
/// free the underlying memory pointed to by the pointer.
///
/// It is undefined behavior for foreign code to dereference the pointer after
/// it has called this method.
#[no_mangle]
pub extern "C" fn mc_error_free(error: FfiOptOwnedPtr<McError>) {
    ffi_boundary(move || {
        let _ = error;
    })
}
