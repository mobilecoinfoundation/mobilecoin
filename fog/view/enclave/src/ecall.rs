// Copyright (c) 2018-2021 The MobileCoin Foundation

///! Forward declarations for ECALL-able methods which live inside an enclave
use mc_sgx_types::{sgx_enclave_id_t, sgx_status_t};

extern "C" {
    pub fn viewenclave_call(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        inbuf: *const u8,
        inbuf_len: usize,
        outbuf: *mut u8,
        outbuf_len: usize,
        outbuf_used: *mut usize,
        outbuf_retry_id: *mut u64,
    ) -> sgx_status_t;
}
