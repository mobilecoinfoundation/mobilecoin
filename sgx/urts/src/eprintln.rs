// Copyright (c) 2018-2021 The MobileCoin Foundation

// Mobilenode-side support for sgx_debug crate impl
//
// Allows dev-build debugging messages similar to eprintln!
// from within the enclave.
//
// We print them to slog because that is our logging infrastructure
//
// Note: This is deprecated and the eprintln should go away, the logger
// API is what you should use.

use mc_common::logger::global_log;
use std::str;

#[no_mangle]
pub unsafe extern "C" fn eprintln_message(msg: *const u8, msg_len: usize) {
    eprintln_message_impl(std::slice::from_raw_parts(msg, msg_len))
}

fn eprintln_message_impl(msg_bytes: &[u8]) {
    match str::from_utf8(msg_bytes) {
        Ok(v) => global_log::info!("Enclave eprintln: {}", v),
        Err(e) => global_log::info!(
            "Enclave eprintln message contained invalid utf8:\n{}\n{:?}",
            e,
            msg_bytes
        ),
    }
}
