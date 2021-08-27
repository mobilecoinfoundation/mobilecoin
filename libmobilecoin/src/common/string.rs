// Copyright (c) 2018-2021 The MobileCoin Foundation

use super::{ffi_boundary, FfiTryFrom, IntoFfi, TryFromFfi};
use crate::LibMcError;
use mc_util_ffi::{FfiOptOwnedStr, FfiOwnedStr, FfiStr};
use std::ffi::CString;

/// All non-null values with a `char *` return (or out parameter) type that are
/// returned to foreign code must call this function in order to free the
/// underlying memory pointed to by the pointer.
///
/// It is undefined behavior for foreign code to dereference the pointer after
/// it has called this method.
#[no_mangle]
pub extern "C" fn mc_string_free(string: FfiOptOwnedStr) {
    ffi_boundary(move || {
        let _ = string;
    })
}

impl IntoFfi<FfiOptOwnedStr> for CString {
    #[inline]
    fn error_value() -> FfiOptOwnedStr {
        FfiOptOwnedStr::null()
    }

    #[inline]
    fn into_ffi(self) -> FfiOptOwnedStr {
        FfiOwnedStr::from(self).into()
    }
}

impl<'a> TryFromFfi<FfiStr<'a>> for &'a str {
    type Error = LibMcError;

    fn try_from_ffi(src: FfiStr<'a>) -> Result<Self, LibMcError> {
        src.as_str()
            .map_err(|err| LibMcError::InvalidInput(format!("Invalid UTF-8: {:?}", err)))
    }
}

impl<'a> TryFromFfi<FfiStr<'a>> for String {
    type Error = LibMcError;

    fn try_from_ffi(src: FfiStr<'a>) -> Result<Self, LibMcError> {
        let str = <&str>::try_from_ffi(src)?;
        Ok(str.to_owned())
    }
}

impl<'a> FfiTryFrom<&str> for FfiOwnedStr {
    type Error = LibMcError;

    #[inline]
    fn ffi_try_from(src: &str) -> Result<Self, LibMcError> {
        FfiOwnedStr::ffi_try_from(src.to_owned())
    }
}

impl<'a> FfiTryFrom<String> for FfiOwnedStr {
    type Error = LibMcError;

    fn ffi_try_from(src: String) -> Result<Self, LibMcError> {
        let c_string = CString::new(src)
            .map_err(|err| LibMcError::InvalidOutput(format!("Unexpected Nul byte: {:?}", err)))?;
        Ok(FfiOwnedStr::new(c_string))
    }
}

impl<'a> FfiTryFrom<Option<&str>> for FfiOptOwnedStr {
    type Error = LibMcError;

    #[inline]
    fn ffi_try_from(src: Option<&str>) -> Result<Self, LibMcError> {
        FfiOptOwnedStr::ffi_try_from(src.map(ToOwned::to_owned))
    }
}

impl<'a> FfiTryFrom<Option<String>> for FfiOptOwnedStr {
    type Error = LibMcError;

    #[inline]
    fn ffi_try_from(src: Option<String>) -> Result<Self, LibMcError> {
        Ok(src.map(FfiOwnedStr::ffi_try_from).transpose()?.into())
    }
}
