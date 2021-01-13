// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]
// This crate provides a panic handler lang item and defines a panic handler
// which logs messages, before calling into either `panic_abort` or
// `panic_unwind`
//
// Provides panic handler lang item, which supports `panic!` and `assert!`
//
// Alloc feature must be enabled to get APIs associated to catching panics
// and rethrowing them, because in Rust those APIs use the Box type.
#![feature(lang_items)] // for eh_personality
#![feature(raw)]
#![feature(thread_local)]
#![feature(unwind_attributes)]
// Enable "untagged unions" when we have alloc feature, used in panicking::try
#![cfg_attr(feature = "alloc", feature(untagged_unions))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use core::any::Any;

mod panicking;

/// panic_strategy module is expected to provide the following interface:
///
/// rust_panic is a private no-mangle function of no particular signature,
///            on which to place breakpoints, always called immediately before
///            a panic happens (and after any logging or payload construction)
///
/// panic_with_payload(Box<Any + Send>) -> !
///            Should take a payload and initiate a panic, doing no additional
///            logging. Should exist only with alloc feature.
///
/// panic_with_info(&PanicInfo) -> !
///            Should initiate a panic, doing no additional logging,
///            constructing a boxed panic payload if needed
///
/// extern "C" fn __rust_maybe_catch_panic(
///        f: fn(*mut u8),
///        data: *mut u8,
///        data_ptr: *mut usize,
///        vtable_ptr: *mut usize,
///    ) -> u32;
///            Should call f(data), catch any exception, and return its payload
///            at data_ptr and vtable_ptr
///
/// panic_strategy module must also provide `eh_personality` lang item
///
#[cfg_attr(feature = "panic_abort", path = "panic_abort/mod.rs")]
mod panic_strategy;

/// This function is meant to be equivalent to std::thread::panicking()
/// Returns true if the thread is currently (unwinding due to) a panic, false
/// otherwise. This is cheap to call, works by checking a thread local counter.
///
pub use panicking::thread_panicking;

/// Invokes a closure, capturing the cause of an unwinding panic if one occurs.
///
/// This function will return `Ok` with the closure's result if the closure
/// does not panic, and will return `Err(cause)` if the closure panics. The
/// `cause` returned is the object with which panic was originally invoked.
///
/// It is currently undefined behavior to unwind from Rust code into foreign
/// code, so this function is particularly useful when Rust is called from
/// another language (normally C). This can run arbitrary Rust code, capturing a
/// panic and allowing a graceful handling of the error.
///
/// It is **not** recommended to use this function for a general try/catch
/// mechanism. The `Result` type is more appropriate to use for functions that
/// can fail on a regular basis. Additionally, this function is not guaranteed
/// to catch all panics, see the "Notes" section below.
///
/// [rfc]: https://github.com/rust-lang/rfcs/blob/master/text/1236-stabilize-catch-panic.md
///
/// # Notes
///
/// Note that this function **may not catch all panics** in Rust. A panic in
/// Rust is not always implemented via unwinding, but can be implemented by
/// aborting the process as well. This function *only* catches unwinding panics,
/// not those that abort the process.
///
#[cfg(feature = "alloc")]
pub fn catch_unwind<F: FnOnce() -> R /*+ UnwindSafe*/, R>(
    f: F,
) -> Result<R, Box<dyn Any + Send + 'static>> {
    unsafe { panicking::try_closure(f) }
}

/// Triggers a panic without invoking the panic hook.
/// Note(chbeck): This is like rethrowing an exception in C++
///
/// This is designed to be used in conjunction with `catch_unwind` to, for
/// example, carry a panic across a layer of C code.
///
/// # Notes
///
/// Note that panics in Rust are not always implemented via unwinding, but they
/// may be implemented by aborting the process. If this function is called when
/// panics are implemented this way then this function will abort the process,
/// not trigger an unwind.
///
#[cfg(feature = "alloc")]
pub fn resume_unwind(payload: Box<dyn Any + Send>) -> ! {
    panicking::rethrow(payload)
}
