// Copyright (c) 2018-2021 The MobileCoin Foundation

use super::panic_strategy;
/// This module defines a `panic_handler` lang item and defines a function
/// `log_and_panic` which does logging as appropriate before calling to
/// `panic_strategy` module to actually initiate a panic.
/// A thread-local panic_counter variable is provided by submodule `panic_counter`
/// which keeps track of how many times we have looped through the panic
/// infrastructure, in order to break recursive panics.
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

// rethrow:
// rethrow a panic
#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use core::any::Any;

// This function is similar to `update_count_and_panic` in rust std panicking.rs
#[cfg(feature = "alloc")]
pub fn rethrow(msg: Box<dyn Any + Send>) -> ! {
    panic_counter::update_panic_count(1);
    panic_strategy::panic_with_payload(msg)
}

/// try_closure:
/// Invoke a closure, capturing the cause of an unwinding panic if one occurs.
#[cfg(feature = "alloc")]
pub unsafe fn try_closure<R, F: FnOnce() -> R>(f: F) -> Result<R, Box<dyn Any + Send>> {
    use self::panic_counter::update_panic_count;
    use core::{mem, mem::ManuallyDrop, raw};

    union Data<F, R> {
        f: ManuallyDrop<F>,
        r: ManuallyDrop<R>,
    }

    // We do some sketchy operations with ownership here for the sake of
    // performance. We can only  pass pointers down to
    // `__rust_maybe_catch_panic` (can't pass objects by value), so we do all
    // the ownership tracking here manually using a union.
    //
    // We go through a transition where:
    //
    // * First, we set the data to be the closure that we're going to call.
    // * When we make the function call, the `do_call` function below, we take
    //   ownership of the function pointer. At this point the `Data` union is
    //   entirely uninitialized.
    // * If the closure successfully returns, we write the return value into the
    //   data's return slot. Note that `ptr::write` is used as it's overwriting
    //   uninitialized data.
    // * Finally, when we come back out of the `__rust_maybe_catch_panic` we're
    //   in one of two states:
    //
    //      1. The closure didn't panic, in which case the return value was
    //         filled in. We move it out of `data` and return it.
    //      2. The closure panicked, in which case the return value wasn't
    //         filled in. In this case the entire `data` union is invalid, so
    //         there is no need to drop anything.
    //
    // Once we stack all that together we should have the "most efficient'
    // method of calling a catch panic whilst juggling ownership.
    let mut any_data = 0;
    let mut any_vtable = 0;
    let mut data = Data {
        f: ManuallyDrop::new(f),
    };

    let r = panic_strategy::__rust_maybe_catch_panic(
        do_call::<F, R>,
        &mut data as *mut _ as *mut u8,
        &mut any_data,
        &mut any_vtable,
    );

    return if r == 0 {
        debug_assert!(update_panic_count(0) == 0);
        Ok(ManuallyDrop::into_inner(data.r))
    } else {
        update_panic_count(-1);
        debug_assert!(update_panic_count(0) == 0);
        Err(mem::transmute(raw::TraitObject {
            data: any_data as *mut _,
            vtable: any_vtable as *mut _,
        }))
    };

    extern "C" fn do_call<F: FnOnce() -> R, R>(data: *mut u8) {
        unsafe {
            let data = data as *mut Data<F, R>;
            let data = &mut (*data);
            let f = ManuallyDrop::take(&mut data.f);
            data.r = ManuallyDrop::new(f());
        }
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
