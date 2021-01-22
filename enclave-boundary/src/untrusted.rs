// Copyright (c) 2018-2021 The MobileCoin Foundation

use alloc::{vec, vec::Vec};
use mc_sgx_types::{sgx_enclave_id_t, sgx_status_t};

// Unified variable-length ECALL signature (from untrusted side)
pub type EcallSig = unsafe extern "C" fn(
    eid: sgx_enclave_id_t,
    retval: *mut sgx_status_t,
    inbuf: *const u8,
    inbuf_len: usize,
    outbuf: *mut u8,
    outbuf_len: usize,
    outbuf_used: *mut usize,
    outbuf_retry_id: *mut u64,
) -> sgx_status_t;

// Untrusted side of the two-step call protocol
pub fn make_variable_length_ecall(
    eid: sgx_enclave_id_t,
    ecall_fcn: EcallSig,
    inbuf: &[u8],
) -> Result<Vec<u8>, sgx_status_t> {
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut outbuf_used = 64usize;
    let mut outbuf_retry_id = 0u64;
    let mut i = 0;
    loop {
        i += 1;
        if i > 2 {
            panic!(
                "enclave_call is broken: i={} outbuf_used={}",
                i, outbuf_used
            );
        }

        let mut outbuf = vec![0u8; outbuf_used];
        match unsafe {
            ecall_fcn(
                eid,
                &mut retval,
                inbuf.as_ptr(),
                inbuf.len(),
                outbuf.as_mut_ptr(),
                outbuf.len(),
                &mut outbuf_used,
                &mut outbuf_retry_id,
            )
        } {
            sgx_status_t::SGX_SUCCESS => match retval {
                sgx_status_t::SGX_ERROR_OUT_OF_MEMORY => continue,
                sgx_status_t::SGX_SUCCESS => {
                    outbuf.truncate(outbuf_used);
                    break Ok(outbuf);
                }
                other_retval => break (Err(other_retval)),
            },
            status => break Err(status),
        }
    }
}
