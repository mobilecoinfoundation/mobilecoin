// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]

#[macro_use]
extern crate alloc;

#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => ($crate::_eprint(format_args!($($arg)*)));
}

pub fn _eprint(args: core::fmt::Arguments) {
    let buf = format!("{}", args);
    unsafe { eprintln_message(buf.as_ptr(), buf.len()) };
}

extern "C" {
    /// This is the OCALL prototype for passing message buffers to the untrusted code. See
    /// sgx_debug_edl crate.
    fn eprintln_message(msg: *const u8, msg_len: usize);
}
