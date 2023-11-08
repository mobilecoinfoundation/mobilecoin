// Copyright (c) 2018-2022 The MobileCoin Foundation

#![no_std]
#![feature(alloc_error_handler)] // for alloc_error_handler

use core::alloc::{GlobalAlloc, Layout};
// use mc_sgx_debug::eprintln;
// use mc_sgx_sync::Mutex;
// use lazy_static::lazy_static;
use core::fmt;
use core::fmt::Write;

/// Byte size of [`WriteBuffer`].
///
/// Attempting to write more than this many bytes to the [`WriteBuffer`] will
/// result in an error.
pub const BUFFER_SIZE: usize = 512;

/// A buffer which implements the [`fmt::Write`] trait.
#[derive(Debug)]
pub struct WriteBuffer {
    buf: [u8; BUFFER_SIZE],
    pos: usize,
}

impl WriteBuffer {
    /// Create a new empty [`WriteBuffer`]
    pub const fn new() -> Self {
        WriteBuffer {
            buf: [0; BUFFER_SIZE],
            pos: 0,
        }
    }

    /// Clear the contents in the [`WriteBuffer`]
    pub fn clear(&mut self) {
        self.pos = 0;
    }
}

impl AsRef<str> for WriteBuffer {
    fn as_ref(&self) -> &str {
        // Shouldn't fail because [`Write::write_str()`] is the only public way
        // to add content. [`Write::write_str()`] takes a `&str` so for this to
        // fail someone must have coerced invalid UTF-8 to a string prior to
        // this method invocation.
        core::str::from_utf8(&self.buf[..self.pos])
            .expect("`WriteBuffer` is not valid UTF-8. It should have only been given `&str`s")
    }
}

impl AsRef<[u8]> for WriteBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.pos]
    }
}

impl fmt::Write for WriteBuffer {
    fn write_str(&mut self, string: &str) -> fmt::Result {
        let bytes = string.as_bytes();

        let remaining = &mut self.buf[self.pos..];
        if remaining.len() < bytes.len() {
            return Err(fmt::Error);
        }

        let new_contents = &mut remaining[..bytes.len()];
        new_contents.copy_from_slice(bytes);

        self.pos += bytes.len();

        Ok(())
    }
}

// Our allocator uses malloc and free exposed by intel libsgx_tstdc
extern "C" {
    // pub fn malloc(size: usize) -> *mut u8;
    pub fn memalign(align: usize, size: usize) -> *mut u8;
    pub fn free(p: *mut u8);
    /// This is the OCALL prototype for passing message buffers to the untrusted
    /// code. See sgx_debug_edl crate.
    fn eprintln_message(msg: *const u8, msg_len: usize);
}

// lazy_static! {
//     static ref TOTAL_HEAP: Mutex<u64> = Mutex::new(0);
// }

// Our allocator definition
struct SgxAllocator;

unsafe impl GlobalAlloc for SgxAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut buf = WriteBuffer::new();
        write!(&mut buf, "ALLOCATING {} bytes", layout.size()).unwrap();
        let contents: &[u8] = buf.as_ref();
        eprintln_message(contents.as_ptr(), contents.len());
        // let memory = TOTAL_HEAP.lock().unwrap();
        // memory.checked_add(layout.size() as u64).unwrap();
        memalign(layout.align(), layout.size())
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // TOTAL_HEAP.lock().unwrap().checked_sub(layout.size() as u64).unwrap();
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
