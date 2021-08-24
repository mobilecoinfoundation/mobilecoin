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
#![feature(thread_local)]
#![feature(unwind_attributes)]
// Enable "untagged unions" when we have alloc feature, used in panicking::try
#![cfg_attr(feature = "alloc", feature(untagged_unions))]

#[cfg(feature = "alloc")]
extern crate alloc;

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
#[cfg_attr(feature = "panic_abort", path = "panic_abort/mod.rs")]
mod panic_strategy;

/// This function is meant to be equivalent to std::thread::panicking()
/// Returns true if the thread is currently (unwinding due to) a panic, false
/// otherwise. This is cheap to call, works by checking a thread local counter.
pub use panicking::thread_panicking;
