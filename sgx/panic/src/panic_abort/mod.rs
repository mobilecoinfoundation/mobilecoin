// Copyright (c) 2018-2021 The MobileCoin Foundation

use core::any::Any;

// There is no catching here because we are always aborting in case of panic,
// so we simply call the function we are passed.
#[no_mangle]
pub unsafe extern "C" fn __rust_maybe_catch_panic(
    f: extern "C" fn(*mut u8),
    data: *mut u8,
    _data_ptr: *mut usize,
    _vtable_ptr: *mut usize,
) -> u32 {
    f(data);
    0
}

pub fn panic_with_info(_: &core::panic::PanicInfo) -> ! {
    rust_panic()
}

#[cfg(feature = "alloc")]
pub fn panic_with_payload(_: alloc::boxed::Box<dyn Any + Send>) -> ! {
    rust_panic()
}

/// A private no-mangle function on which to slap yer breakpoints.
#[no_mangle]
pub fn rust_panic() -> ! {
    // This is the sgx function that we are supposed to call to abort
    // From intel sgx_trts C library
    extern "C" {
        pub fn abort() -> !;
    }

    unsafe { abort() }
}

// Rustc says we need this, but since we abort on panic, it won't ever
// actually be used.
// More here on SO:
// https://stackoverflow.com/questions/16597350/what-is-an-exception-handling-personality-function
//
// Note that this is provided in `libpanic_abort` currently in rust tree
#[lang = "eh_personality"]
fn rust_eh_personality() {}
