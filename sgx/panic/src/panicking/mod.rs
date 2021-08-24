// Copyright (c) 2018-2021 The MobileCoin Foundation

use super::panic_strategy;
/// This module defines a `panic_handler` lang item and defines a function
/// `log_and_panic` which does logging as appropriate before calling to
/// `panic_strategy` module to actually initiate a panic.
/// A thread-local panic_counter variable is provided by submodule
/// `panic_counter` which keeps track of how many times we have looped through
/// the panic infrastructure, in order to break recursive panics.
/// The `try` function takes a closure and submits it to the panic_strategy,
/// taking care to return the results in a nice format and decremeent the
/// panic_counter in case a panic was caught.
/// rethrow function is used to rethrow exceptions... err, panics.
use core::panic::PanicInfo;

// Get formatting helper
mod format_helper;

// Counter for recursive panics
mod panic_counter;

/// Determines whether the current thread is unwinding because of panic.
/// Analogous to std::thread::panicking()
pub fn thread_panicking() -> bool {
    panic_counter::update_panic_count(0) != 0
}

/// Entry point of panic from the libcore crate.
#[panic_handler]
#[unwind(allowed)]
fn rust_begin_panic(info: &PanicInfo) -> ! {
    log_and_panic(info)
}

// Implements primary logic for panic
// 1. Try to log a message
// 2. Call into __rust_start_panic hook
//
// with a guard to try to prevent infinite loops if one of these calls panics
//
// This is analogous to `rust_panic_with_hook` in rust std `panicking.rs` module
#[inline(never)]
#[cold]
fn log_and_panic(info: &PanicInfo) -> ! {
    let panics = panic_counter::update_panic_count(1);

    if panics > 2 {
        hard_abort("thread panicked while processing a panic, aborting")
    }

    format_helper::report_panic_text(format_args!("{}", info));

    if panics > 1 {
        hard_abort("thread panicked while processing a panic, aborting")
    }

    panic_strategy::panic_with_info(info)
}

/// Pass a string (with no formatting) to untrusted and then abort
/// This can be used as a fallback if the panic handler appears to have failed
/// Note(chbeck): This is public so that panic_unwind can use it, which is a
/// bit hacky, but not too bad since it doesn't escape to public of crate.
#[inline(never)]
#[cold]
pub fn hard_abort(msg: &'static str) -> ! {
    format_helper::report_panic_str(msg);
    unsafe { abort() }

    // From intel sgx_trts C library
    extern "C" {
        pub fn abort() -> !;
    }
}

// These functions are implemented in panic_abort or panic_unwind according
// to the user's choice

#[allow(improper_ctypes)]
extern "C" {
    fn __rust_maybe_catch_panic(
        f: fn(*mut u8),
        data: *mut u8,
        data_ptr: *mut usize,
        vtable_ptr: *mut usize,
    ) -> u32;
    #[unwind(allowed)]
    fn __rust_start_panic(data: usize, vtable: usize) -> u32;
}
