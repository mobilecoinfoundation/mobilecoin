// Copyright (c) 2018-2020 MobileCoin Inc.

// Mobilenode-side support for sgx_debug crate impl
//
// Allows dev-build debugging messages similar to eprintln!

use std::str;

#[no_mangle]
pub extern "C" fn eprintln_message(msg: *const u8, msg_len: usize) {
    let msg_bytes = unsafe { std::slice::from_raw_parts(msg, msg_len) };

    match str::from_utf8(msg_bytes) {
        Ok(v) => eprintln!("Enclave log: {}", v),
        Err(e) => eprintln!(
            "Enclave log message contained invalid utf8:\n{}\n{:?}",
            e, msg_bytes
        ),
    }
}
