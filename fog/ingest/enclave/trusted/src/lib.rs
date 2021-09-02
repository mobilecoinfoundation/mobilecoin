// Copyright (c) 2018-2021 The MobileCoin Foundation

//! MobileCoin Fog Ingest Enclave

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::slice;
use lazy_static::lazy_static;
use mc_enclave_boundary::trusted::RetryBuffer;
use mc_fog_ingest_enclave_api::{EnclaveCall, IngestEnclave};
use mc_fog_ingest_enclave_impl::SgxIngestEnclave;
use mc_fog_ocall_oram_storage_trusted::OcallORAMStorageCreator;
use mc_sgx_compat::panic::catch_unwind;
use mc_sgx_report_cache_api::ReportableEnclave;
use mc_sgx_slog::default_logger;
use mc_sgx_types::{c_void, sgx_is_outside_enclave, sgx_status_t};
use mc_util_serial::{deserialize, serialize};

lazy_static! {
    /// Storage for ECALL results whose given outbuf was not large enough
    static ref RETRY_BUFFER: RetryBuffer = RetryBuffer::new(&ecall_dispatcher);

    /// Storage for the business logic / implementation state
    static ref ENCLAVE: SgxIngestEnclave<OcallORAMStorageCreator> = SgxIngestEnclave::new(default_logger());
}

/// Dispatch ecalls with the unified signature
pub fn ecall_dispatcher(inbuf: &[u8]) -> Result<Vec<u8>, sgx_status_t> {
    // Figure out what we're trying to do
    let call_details: EnclaveCall =
        deserialize(inbuf).or(Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER))?;

    // And actually do it
    let outdata = match call_details {
        // Utility methods
        EnclaveCall::EnclaveInit(params) => {
            serialize(&ENCLAVE.enclave_init(params)).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }

        EnclaveCall::NewKeys => {
            serialize(&ENCLAVE.new_keys()).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }

        EnclaveCall::NewEgressKey => {
            serialize(&ENCLAVE.new_egress_key()).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }

        // Public Key for Fog Hints
        EnclaveCall::GetIngressPubkey => {
            serialize(&ENCLAVE.get_ingress_pubkey()).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }

        EnclaveCall::GetSealedIngressPrivateKey => {
            serialize(&ENCLAVE.get_sealed_ingress_private_key())
                .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }

        EnclaveCall::GetIngressPrivateKey(peer_session) => {
            serialize(&ENCLAVE.get_ingress_private_key(peer_session))
                .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }

        EnclaveCall::SetIngressPrivateKey(msg) => serialize(&ENCLAVE.set_ingress_private_key(msg))
            .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?,

        // Public key for rng's
        EnclaveCall::GetKexRngPubkey => {
            serialize(&ENCLAVE.get_kex_rng_pubkey()).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }

        EnclaveCall::IngestTxs(chunk) => {
            serialize(&ENCLAVE.ingest_txs(chunk)).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }

        // Report Caching
        EnclaveCall::GetIdentity => {
            serialize(&ENCLAVE.get_identity()).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }

        EnclaveCall::NewEreport(qe_info) => {
            serialize(&ENCLAVE.new_ereport(qe_info)).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }

        EnclaveCall::VerifyQuote(quote, qe_report) => {
            serialize(&ENCLAVE.verify_quote(quote, qe_report))
                .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }

        EnclaveCall::VerifyReport(ias_report) => serialize(&ENCLAVE.verify_ias_report(ias_report))
            .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?,

        EnclaveCall::GetReport => {
            serialize(&ENCLAVE.get_ias_report()).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }

        EnclaveCall::PeerInit(peer_id) => {
            serialize(&ENCLAVE.peer_init(&peer_id)).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }

        EnclaveCall::PeerAccept(req) => {
            serialize(&ENCLAVE.peer_accept(req)).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }

        EnclaveCall::PeerConnect(peer_id, msg) => serialize(&ENCLAVE.peer_connect(&peer_id, msg))
            .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?,

        EnclaveCall::PeerClose(session_id) => serialize(&ENCLAVE.peer_close(&session_id))
            .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?,
    };

    Ok(outdata)
}

/// The entry point implementation for ingest_enclave_api
///
/// See ingest_enclave_api::mobileenclave() declaration for more information
#[no_mangle]
pub extern "C" fn ingest_enclave_call(
    inbuf: *const u8,
    inbuf_len: usize,
    outbuf: *mut u8,
    outbuf_len: usize,
    outbuf_used: *mut usize,
    outbuf_retry_id: *mut u64,
) -> sgx_status_t {
    if inbuf.is_null()
        || outbuf.is_null()
        || outbuf_used.is_null()
        || outbuf_retry_id.is_null()
        || unsafe { sgx_is_outside_enclave(inbuf as *const c_void, inbuf_len) } == 1
        || unsafe { sgx_is_outside_enclave(outbuf as *const c_void, outbuf_len) } != 1
        || unsafe {
            sgx_is_outside_enclave(outbuf_used as *const c_void, core::mem::size_of::<usize>())
        } != 1
        || unsafe {
            sgx_is_outside_enclave(
                outbuf_retry_id as *const c_void,
                core::mem::size_of::<u64>(),
            )
        } != 1
    {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    match catch_unwind(|| {
        let mut temp_outbuf_used = unsafe { *outbuf_used };
        let mut temp_outbuf_retry_id = unsafe { *outbuf_retry_id };
        let res = RETRY_BUFFER.call(
            unsafe { slice::from_raw_parts(inbuf, inbuf_len) },
            unsafe { slice::from_raw_parts_mut(outbuf, outbuf_len) },
            &mut temp_outbuf_used,
            &mut temp_outbuf_retry_id,
        );
        unsafe {
            *outbuf_used = temp_outbuf_used;
            *outbuf_retry_id = temp_outbuf_retry_id;
        }
        res
    }) {
        Ok(x) => match x {
            Ok(_) => sgx_status_t::SGX_SUCCESS,
            Err(retval) => retval,
        },
        Err(_) => sgx_status_t::SGX_ERROR_ENCLAVE_CRASHED,
    }
}
