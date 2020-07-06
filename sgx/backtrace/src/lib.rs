// Copyright (c) 2018-2020 MobileCoin Inc.

#![no_std]
#![feature(llvm_asm)]

/// Provide support for getting backtraces in sgx, and sending them to untrusted
/// as well as setting and getting the enclave path to aid symbolication
extern crate mc_sgx_libc_types as libc;
extern crate mc_sgx_unwind as unwind;

#[cfg(feature = "sgx_debug")]
#[macro_use]
extern crate mc_sgx_debug;

// Provide `unwind_backtrace` for obtaining backtrace frames
pub mod tracing;

// Provide `send_backtrace` for sending backtraces to untrusted
pub mod sending;

// This is the layout of "frame" that we use, also as an FFI type
pub use libc::Frame;

use core::cmp;

/// Simplest interface: Collect a backtrace and send it
pub fn collect_and_send_backtrace() {
    const NB_FRAMES: usize = 100;
    let mut frames: [Frame; NB_FRAMES] = unsafe { core::mem::zeroed() };

    let nframes = tracing::unwind_backtrace(&mut frames).unwrap_or_else(|_| {
        #[cfg(feature = "sgx_debug")]
        eprintln!("Unexpected return value while unwinding");
        0
    });

    let eid = mc_sgx_enclave_id::get_enclave_id();

    sending::send_backtrace(eid, &frames[..cmp::min(nframes, NB_FRAMES)]);
}
