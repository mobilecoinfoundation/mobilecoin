// Copyright (c) 2018-2021 The MobileCoin Foundation

use alloc::{boxed::Box, vec::Vec};

use mc_common::HashMap;
use mc_crypto_rand::McRng;
use mc_sgx_compat::sync::Mutex;
use mc_sgx_types::sgx_status_t;
use rand_core::RngCore;

pub struct RetryBuffer {
    retry_data: Mutex<HashMap<u64, Vec<u8>>>,
    handler: Box<dyn Fn(&[u8]) -> Result<Vec<u8>, sgx_status_t> + Send + Sync>,
}

impl RetryBuffer {
    pub fn new<F>(fcn: F) -> Self
    where
        F: Fn(&[u8]) -> Result<Vec<u8>, sgx_status_t> + 'static + Send + Sync,
    {
        Self {
            retry_data: Mutex::new(Default::default()),
            handler: Box::new(fcn),
        }
    }

    // Logic of call, which is close to the ecall
    pub fn call(
        &self,
        inbuf: &[u8],
        outbuf: &mut [u8],
        outbuf_used: &mut usize,
        outbuf_retry_id: &mut u64,
    ) -> Result<(), sgx_status_t> {
        // if this is a outbuf resize retry, try to fulfil it
        if *outbuf_retry_id > 0 {
            // grab a lock on the retry data
            let mut retry_guard = self
                .retry_data
                .lock()
                .or(Err(sgx_status_t::SGX_ERROR_ENCLAVE_CRASHED))?;

            // get the outdata, if any
            let outdata = retry_guard
                .remove(outbuf_retry_id)
                .ok_or(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)?;

            let outdata_len = outdata.len();
            // Still not big enough, insert the output back into the retry data
            if outdata_len > outbuf.len() {
                retry_guard.insert(*outbuf_retry_id, outdata);
                *outbuf_used = outdata_len;
                return Err(sgx_status_t::SGX_ERROR_OUT_OF_MEMORY);
            }

            // otherwise copy the retry data into the outbuf
            outbuf[..outdata_len].copy_from_slice(&outdata);
            *outbuf_used = outdata_len;
            *outbuf_retry_id = 0;
            return Ok(());
        }

        // Dispatch to handler
        let outdata = (self.handler)(inbuf)?;

        // If we don't have enough buffer to serialize the output, save
        // the output and return a retry ID.
        let outdata_len = outdata.len();
        if outdata_len > outbuf.len() {
            let mut csprng = McRng::default();
            let mut retry_guard = self
                .retry_data
                .lock()
                .or(Err(sgx_status_t::SGX_ERROR_ENCLAVE_CRASHED))?;
            let retry_id = loop {
                let retry_id = csprng.next_u64();
                if !(*retry_guard).contains_key(&retry_id) {
                    break retry_id;
                }
            };
            (*retry_guard).insert(retry_id, outdata);
            *outbuf_used = outdata_len;
            *outbuf_retry_id = retry_id;
            return Err(sgx_status_t::SGX_ERROR_OUT_OF_MEMORY);
        }

        outbuf[..outdata_len].copy_from_slice(&outdata);
        *outbuf_used = outdata_len;
        *outbuf_retry_id = 0;
        Ok(())
    }
}
