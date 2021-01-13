// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]
#![feature(alloc_error_handler)] // for alloc_error_handler

use core::alloc::{GlobalAlloc, Layout};

// Our allocator uses malloc and free exposed by intel libsgx_tstdc
extern "C" {
    // pub fn malloc(size: usize) -> *mut u8;
    pub fn memalign(align: usize, size: usize) -> *mut u8;
    pub fn free(p: *mut u8);
}

// Our allocator definition
struct SgxAllocator;

unsafe impl GlobalAlloc for SgxAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        memalign(layout.align(), layout.size())
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        free(ptr)
    }
}

// Installation of global allocator
#[global_allocator]
static A: SgxAllocator = SgxAllocator;

// Define oom handler in terms of panicking
// Docu: https://doc.rust-lang.org/unstable-book/language-features/alloc-error-handler.html
#[cfg(feature = "oom_panic")]
#[alloc_error_handler]
fn oom(layout: core::alloc::Layout) -> ! {
    panic!("OOM: Failed to allocate {} bytes", layout.size())
}

// Define oom handler by simply aborting, if user doesn't want to bring in
// panic support etc.
#[cfg(feature = "oom_abort")]
#[alloc_error_handler]
fn oom(_layout: core::alloc::Layout) -> ! {
    unsafe { abort() }

    // From intel sgx_trts C library
    extern "C" {
        pub fn abort() -> !;
    }
}
