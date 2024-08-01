// Copyright (c) 2018-2023 The MobileCoin Foundation

// Mobilenode-side support for sgx_panic crate impl
//
// If the enclave panics, it will pass us a message, which we log as critical.
// The enclave is expected to call rsgx_abort itself after this

use mc_common::logger::global_log;
use std::str;

#[no_mangle]
pub unsafe extern "C" fn report_panic_message(msg: *const u8, msg_len: usize) {
    report_panic_message_impl(std::slice::from_raw_parts(msg, msg_len))
}

fn report_panic_message_impl(panic_msg_bytes: &[u8]) {
    match str::from_utf8(panic_msg_bytes) {
        // We log to both STDERR and the slog interface, which goes to STDOUT.
        // The reasoning is, we want most stuff to be directed at slog, because
        // that's what our production logging is picking up right now, and
        // those logs will have timing, source data, etc.
        // However, when running locally in SGX_MODE=SW, what typically happens
        // during an enclave panic is that the process crashes almost immediately
        // after this OCALL returns, and slog doesn't manage to flush its buffer
        // before the process dies, which makes it hard for a dev to debug.
        // By logging to STDERR also we make sure the message gets to an OS
        // buffer before the process dies.
        Ok(v) => {
            eprintln!("Enclave panic: {}", v);
            global_log::crit!("Enclave panic: {}", v)
        },
        Err(e) => {
            eprintln!("Enclave panic message contained invalid utf8: ({}) {:?}", e, panic_msg_bytes);
            global_log::crit!(
                "Enclave panic message contained invalid utf8: ({}) {:?}",
                e,
                panic_msg_bytes
            )
        },
    }
}
