// Copyright (c) 2018-2022 The MobileCoin Foundation

//! View Enclave Trusted

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::slice;
use mc_enclave_boundary::trusted::RetryBuffer;
use mc_fog_ocall_oram_storage_trusted::OcallORAMStorageCreator;
use mc_fog_view_enclave_api::{ViewEnclaveApi, ViewEnclaveRequest};
use mc_fog_view_enclave_impl::ViewEnclave;
use mc_sgx_compat::{eprintln, panic::catch_unwind};
use mc_sgx_report_cache_api::ReportableEnclave;
use mc_sgx_slog::default_logger;
use mc_sgx_types::{c_void, sgx_is_outside_enclave, sgx_status_t};
use mc_util_serial::{deserialize, serialize};

lazy_static::lazy_static! {
    static ref RETRY_BUFFER: RetryBuffer = RetryBuffer::new(&ecall_dispatcher);
}

/// The entry point implementation for test_enclave_api
///
/// See test_enclave_api declaration for more information
#[no_mangle]
pub extern "C" fn viewenclave_call(
    inbuf: *const u8,
    inbuf_len: usize,
    outbuf: *mut u8,
    outbuf_len: usize,
    outbuf_used: *mut usize,
    outbuf_retry_id: *mut u64,
) -> sgx_status_t {
    if inbuf.is_null()
        || outbuf.is_null()
        || unsafe { sgx_is_outside_enclave(inbuf as *const c_void, inbuf_len) } == 1
        || unsafe { sgx_is_outside_enclave(outbuf as *const c_void, outbuf_len) } == 1
    {
        eprintln!("inbuf or outbuf was out of bounds!");
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    if unsafe {
        sgx_is_outside_enclave(outbuf_used as *const c_void, core::mem::size_of::<usize>())
    } == 1
    {
        eprintln!("outbuf_used was out of bounds! {:?}", outbuf_used);
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    if unsafe {
        sgx_is_outside_enclave(
            outbuf_retry_id as *const c_void,
            core::mem::size_of::<u64>(),
        )
    } == 1
    {
        eprintln!("outbuf_retry_id was out of bounds! {:?}", outbuf_retry_id);
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    match catch_unwind(|| {
        let mut temp_outbuf_used = unsafe { *outbuf_used };
        let mut temp_outbuf_retry_id = unsafe { *outbuf_retry_id };
        let ret = RETRY_BUFFER.call(
            unsafe { slice::from_raw_parts(inbuf, inbuf_len) },
            unsafe { slice::from_raw_parts_mut(outbuf, outbuf_len) },
            &mut temp_outbuf_used,
            &mut temp_outbuf_retry_id,
        );
        unsafe {
            *outbuf_used = temp_outbuf_used;
        }
        unsafe {
            *outbuf_retry_id = temp_outbuf_retry_id;
        }
        ret
    }) {
        Ok(x) => match x {
            Ok(_) => sgx_status_t::SGX_SUCCESS,
            Err(retval) => retval,
        },
        Err(_) => sgx_status_t::SGX_ERROR_ENCLAVE_CRASHED,
    }
}

// The actual dispatcher and state associated to it

lazy_static::lazy_static! {
    static ref ENCLAVE: ViewEnclave<OcallORAMStorageCreator> = ViewEnclave::new(default_logger());
}

pub fn ecall_dispatcher(inbuf: &[u8]) -> Result<Vec<u8>, sgx_status_t> {
    // Figure out what we're trying to do
    let call_details: ViewEnclaveRequest = deserialize(inbuf).map_err(|err| {
        eprintln!("ecall_dispatcher: could not deserialize request: {}", err);
        sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    })?;

    // And actually do it
    match call_details {
        ViewEnclaveRequest::Init(params) => {
            mc_sgx_enclave_id::set_enclave_id(params.eid);
            serialize(&ENCLAVE.init(params))
        }
        ViewEnclaveRequest::GetIdentity => mc_util_serial::serialize(&ENCLAVE.get_identity()),
        ViewEnclaveRequest::NewEReport(target_info) => serialize(&ENCLAVE.new_ereport(target_info)),
        ViewEnclaveRequest::VerifyQuote(quote, report) => {
            serialize(&ENCLAVE.verify_quote(quote, report))
        }
        ViewEnclaveRequest::VerifyIasReport(verification_report) => {
            serialize(&ENCLAVE.verify_ias_report(verification_report))
        }
        ViewEnclaveRequest::GetIasReport => serialize(&ENCLAVE.get_ias_report()),
        ViewEnclaveRequest::ClientAccept(msg) => serialize(&ENCLAVE.client_accept(msg)),
        ViewEnclaveRequest::ViewStoreInit(view_store_id) => serialize(&ENCLAVE.view_store_init(view_store_id)),
        ViewEnclaveRequest::ViewStoreConnect(view_store_id, msg) => serialize(&ENCLAVE.view_store_connect(view_store_id, msg)),
        ViewEnclaveRequest::ClientClose(session) => serialize(&ENCLAVE.client_close(session)),
        ViewEnclaveRequest::Query(req, untrusted_query_response) => {
            serialize(&ENCLAVE.query(req, untrusted_query_response))
        }
        ViewEnclaveRequest::AddRecords(records) => serialize(&ENCLAVE.add_records(records)),
        ViewEnclaveRequest::CreateMultiViewStoreQuery(client_query) => {
            serialize(&ENCLAVE.create_multi_view_store_query_data(client_query))
        }
    }
    .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))
}
