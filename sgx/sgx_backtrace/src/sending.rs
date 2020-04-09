// Copyright (c) 2018-2020 MobileCoin Inc.

use super::Frame;
use sgx_types::sgx_enclave_id_t;

pub fn send_backtrace(eid: sgx_enclave_id_t, frames: &[Frame]) {
    unsafe { report_backtrace(eid, frames.as_ptr(), frames.len()) }

    // This is the ocall that we use to report a backtrace
    extern "C" {
        pub fn report_backtrace(eid: sgx_enclave_id_t, frames: *const Frame, nframes: usize);
    }
}
