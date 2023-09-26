// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mobilenode Ledger Enclave

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::slice;
use lazy_static::lazy_static;
use mc_enclave_boundary::trusted::RetryBuffer;
use mc_fog_ledger_enclave_api::{EnclaveCall, LedgerEnclave};
use mc_fog_ledger_enclave_impl::SgxLedgerEnclave;
use mc_fog_ocall_oram_storage_trusted::OcallORAMStorageCreator;
use mc_sgx_compat::panic::catch_unwind;
use mc_sgx_report_cache_api::ReportableEnclave;
use mc_sgx_slog::default_logger;
use mc_sgx_types::{c_void, sgx_is_outside_enclave, sgx_status_t};
use mc_util_serial::{deserialize, serialize};

lazy_static! {
    /// Storage for ECALL results whose given outbuf was not large enough
    static ref RETRY_BUFFER: RetryBuffer = RetryBuffer::new(ecall_dispatcher);

    /// Storage for business logic / implementation state of ledger enclave
    static ref ENCLAVE: SgxLedgerEnclave<OcallORAMStorageCreator> = SgxLedgerEnclave::new(default_logger());
}

/// Dispatch ecalls with the unified signature
pub fn ecall_dispatcher(inbuf: &[u8]) -> Result<Vec<u8>, sgx_status_t> {
    // Figure out what we're trying to do
    let call_details: EnclaveCall =
        deserialize(inbuf).or(Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER))?;

    // And actually do it
    match call_details {
        // Utility methods
        EnclaveCall::EnclaveInit(self_id, desired_capacity) => {
            serialize(&ENCLAVE.enclave_init(&self_id, desired_capacity))
        }
        // Node-to-Client Attestation
        EnclaveCall::ClientAccept(auth_msg) => serialize(&ENCLAVE.client_accept(auth_msg)),
        EnclaveCall::ClientClose(channel_id) => serialize(&ENCLAVE.client_close(channel_id)),
        // Report Caching
        EnclaveCall::GetIdentity => serialize(&ENCLAVE.get_identity()),
        EnclaveCall::NewEreport(qe_info) => serialize(&ENCLAVE.new_ereport(qe_info)),
        EnclaveCall::VerifyQuote(quote, qe_report, report_data) => {
            serialize(&ENCLAVE.verify_quote(quote, qe_report, report_data))
        }
        EnclaveCall::VerifyAttestationEvidence(attestation_evidence) => {
            serialize(&ENCLAVE.verify_attestation_evidence(attestation_evidence))
        }
        EnclaveCall::GetAttestationEvidence => serialize(&ENCLAVE.get_attestation_evidence()),
        // Outputs
        EnclaveCall::GetOutputs(msg) => serialize(&ENCLAVE.get_outputs(msg)),
        EnclaveCall::GetOutputsData(resp, client) => {
            serialize(&ENCLAVE.get_outputs_data(resp, client))
        }
        // Check Key image
        EnclaveCall::CheckKeyImages(req, response) => {
            serialize(&ENCLAVE.check_key_images(req, response))
        }
        // Add Key Image Data
        EnclaveCall::AddKeyImageData(records) => serialize(&ENCLAVE.add_key_image_data(records)),

        // Router / Store system
        // Router-side
        EnclaveCall::LedgerStoreInit(responder_id) => {
            serialize(&ENCLAVE.ledger_store_init(responder_id))
        }
        EnclaveCall::LedgerStoreConnect(responder_id, client_auth_response) => {
            serialize(&ENCLAVE.ledger_store_connect(responder_id, client_auth_response))
        }
        EnclaveCall::DecryptAndSealQuery(client_query) => {
            serialize(&ENCLAVE.decrypt_and_seal_query(client_query))
        }
        EnclaveCall::CreateMultiKeyImageStoreQueryData(msg) => {
            serialize(&ENCLAVE.create_multi_key_image_store_query_data(msg))
        }
        EnclaveCall::CollateQueryResponses(sealed_query, shard_query_responses) => {
            serialize(&ENCLAVE.collate_shard_query_responses(sealed_query, shard_query_responses))
        }
        EnclaveCall::CheckKeyImageStore(req, response) => {
            serialize(&ENCLAVE.check_key_image_store(req, response))
        }
        EnclaveCall::FrontendAccept(auth_message) => {
            serialize(&ENCLAVE.frontend_accept(auth_message))
        }
    }
    .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))
}

/// The entry point implementation for ledger_enclave_api
///
/// See ledger_enclave_api::mobileenclave() declaration for more information
/// # Safety
/// This method dereferences raw pointers and is therefore unsafe.
#[no_mangle]
pub unsafe extern "C" fn ledger_enclave_call(
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
        || unsafe { sgx_is_outside_enclave(outbuf as *const c_void, outbuf_len) } == 1
        || unsafe {
            sgx_is_outside_enclave(outbuf_used as *const c_void, core::mem::size_of::<usize>())
        } == 1
        || unsafe {
            sgx_is_outside_enclave(
                outbuf_retry_id as *const c_void,
                core::mem::size_of::<u64>(),
            )
        } == 1
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
