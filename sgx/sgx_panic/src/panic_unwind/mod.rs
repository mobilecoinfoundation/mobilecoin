// Copyright (c) 2018-2020 MobileCoin Inc.

extern crate sgx_libc_types as libc;
extern crate sgx_unwind as unwind;

use super::panicking::hard_abort;

use alloc::boxed::Box;
use core::{any::Any, intrinsics, mem, panic::PanicInfo, raw};

pub mod dwarf;

// See rust libpanic_unwind if you want to try to make this more portable
#[path = "gcc.rs"]
mod imp;

// Entry point for catching an exception, implemented using the `try` intrinsic
// in the compiler.
//
// The interaction between the `payload` function and the compiler is pretty
// hairy and tightly coupled, for more information see the compiler's
// implementation of this.
#[no_mangle]
pub unsafe extern "C" fn __rust_maybe_catch_panic(
    f: fn(*mut u8),
    data: *mut u8,
    data_ptr: *mut usize,
    vtable_ptr: *mut usize,
) -> u32 {
    let mut payload = imp::payload();
    if intrinsics::r#try(f, data, &mut payload as *mut _ as *mut _) == 0 {
        0
    } else {
        let obj = mem::transmute::<_, raw::TraitObject>(imp::cleanup(payload));
        *data_ptr = obj.data as usize;
        *vtable_ptr = obj.vtable as usize;
        1
    }
}

// Entry point for raising an exception, just delegates to the platform-specific
// implementation.
// no_mangle so you can put breakpoints on it
#[no_mangle]
#[unwind(allowed)]
unsafe fn rust_panic(payload: Box<dyn Any + Send>) -> u32 {
    imp::panic(payload)
}

pub fn panic_with_payload(payload: Box<dyn Any + Send>) -> ! {
    unsafe { rust_panic(payload) };
    hard_abort("Failed to initiate panic")
}

pub fn panic_with_info(info: &PanicInfo) -> ! {
    // Note(chbeck): It's annoying that we have to make an allocation
    // here, which could fail. It's not clear what alternative we have though,
    // we have to get the string off the stack because we are going to unwind.
    // It would be nicer if info.payload() had a long lifetime so we could just
    // store that.
    // Currently in rust std tree they just make a new string here.
    use alloc::string::String;
    use core::fmt::Write;
    let mut payload = String::new();
    drop(payload.write_fmt(match info.message() {
        Some(args) => *args,
        None => format_args!("Cause unknown"),
    }));
    panic_with_payload(Box::new(payload))
}
