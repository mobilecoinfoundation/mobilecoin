// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{common::*, LibMcError};
use libc::ssize_t;
use mc_api::printable::PrintableWrapper;
use mc_util_ffi::*;
use protobuf::Message;

/* ==== PrintableWrapper ==== */

impl<'a> TryFromFfi<&McBuffer<'a>> for PrintableWrapper {
    type Error = LibMcError;

    fn try_from_ffi(src: &McBuffer<'a>) -> Result<Self, Self::Error> {
        Self::parse_from_bytes(&src).map_err(|err| LibMcError::InvalidInput(format!("{:?}", err)))
    }
}

/// # Preconditions
///
/// * `printable_wrapper_proto_bytes` - must be a valid binary-serialized
///   `printable.PrintableWrapper` Protobuf.
#[no_mangle]
pub extern "C" fn mc_printable_wrapper_b58_encode(
    printable_wrapper_proto_bytes: FfiRefPtr<McBuffer>,
) -> FfiOptOwnedStr {
    ffi_boundary(|| {
        let printable_wrapper = PrintableWrapper::try_from_ffi(&printable_wrapper_proto_bytes)
            .expect("printable_wrapper_proto_bytes could not be converted to PrintableWrapper");
        let encoded = printable_wrapper
            .b58_encode()
            .expect("printable_wrapper could not be encoded as base-58");

        FfiOwnedStr::ffi_try_from(encoded)
            .expect("Resulting encoded string could not be converted to a C string")
    })
}

/// # Preconditions
///
/// * `b58_encoded_string` - must be a nul-terminated C string containing valid
///   UTF-8.
/// * `out_printable_wrapper_proto_bytes` - must be null or else length must be
///   >= `wrapper_bytes.len`.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_printable_wrapper_b58_decode(
    b58_encoded_string: FfiStr,
    out_printable_wrapper_proto_bytes: FfiOptMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> ssize_t {
    ffi_boundary_with_error(out_error, || {
        let b58_encoded_string =
            String::try_from_ffi(b58_encoded_string).expect("b58_encoded_string is invalid");

        let printable_wrapper = PrintableWrapper::b58_decode(b58_encoded_string)?;
        let wrapper_bytes = printable_wrapper.write_to_bytes()?;

        if let Some(out_printable_wrapper_proto_bytes) =
            out_printable_wrapper_proto_bytes.into_option()
        {
            out_printable_wrapper_proto_bytes
                .into_mut()
                .as_slice_mut_of_len(wrapper_bytes.len())
                .expect("out_printable_wrapper_proto_bytes length is insufficient")
                .copy_from_slice(&wrapper_bytes);
        }
        Ok(ssize_t::ffi_try_from(wrapper_bytes.len())
            .expect("wrapper_bytes.len could not be converted to ssize_t"))
    })
}
