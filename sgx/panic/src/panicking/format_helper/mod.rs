// Copyright (c) 2018-2021 The MobileCoin Foundation

use core::fmt::{self, Write};

mod workaround; //Shepmaster's workaround for core::fmt::Write to a fixed buffer

// Maximum supported message length
const MAX_MSG_SIZE: usize = 4096;

// Try to format message onto the stack in a buffer of MAX_MSG_SIZE,
// and report this to the untrusted code.
// If there isn't enough space, report the fallback string instead.
//
// Example usage:
// report_panic_text(format_args!("My foo bar is {}", status));
pub fn report_panic_text(message: fmt::Arguments) {
    let mut buf = [0u8; MAX_MSG_SIZE];
    let mut wrapper = workaround::Wrapper::new(&mut buf);

    match Write::write_fmt(&mut wrapper, message) {
        Ok(_) => {
            unsafe { report_panic_message(wrapper.get_buf().as_ptr(), wrapper.get_offset()) };
        }
        Err(_) => {
            let fallback = "sgx_panic: The panic message exceeded MAX_MSG_SIZE bytes";
            report_panic_str(fallback)
        }
    };

    #[cfg(feature = "sgx_backtrace")]
    mc_sgx_backtrace::collect_and_send_backtrace();
}

// Report fixed string, with no formatting work
pub fn report_panic_str(message: &'static str) {
    unsafe { report_panic_message(message.as_ptr(), message.len()) }
}

// This is the ocall that we use to make to report panic text
// See src/sgx/edl/
extern "C" {
    pub fn report_panic_message(msg: *const u8, msg_len: usize);
}
