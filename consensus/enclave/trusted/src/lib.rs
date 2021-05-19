// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Mobilenode Consensus Enclave

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::slice;
use lazy_static::lazy_static;
use mc_consensus_enclave_api::{ConsensusEnclave, EnclaveCall};
use mc_consensus_enclave_impl::SgxConsensusEnclave;
use mc_enclave_boundary::trusted::RetryBuffer;
use mc_sgx_compat::panic::catch_unwind;
use mc_sgx_report_cache_api::ReportableEnclave;
use mc_sgx_types::{c_void, sgx_is_outside_enclave, sgx_status_t};
use mc_util_serial::{deserialize, serialize};

lazy_static! {
    /// Storage for ECALL results whose given outbuf was not large enough
    static ref RETRY_BUFFER: RetryBuffer = RetryBuffer::new(&ecall_dispatcher);

    /// Storage for the business logic / implementation state
    static ref ENCLAVE: SgxConsensusEnclave = SgxConsensusEnclave::new(mc_sgx_slog::default_logger());
}

/// Dispatch ecalls with the unified signature
pub fn ecall_dispatcher(inbuf: &[u8]) -> Result<Vec<u8>, sgx_status_t> {
    // Figure out what we're trying to do
    let call_details: EnclaveCall =
        deserialize(inbuf).or(Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER))?;

    // And actually do it
    let outdata = match call_details {
        // Utility methods
        EnclaveCall::EnclaveInit(peer_self_id, client_self_id, sealed_key, minimum_fee) => {
            serialize(&ENCLAVE.enclave_init(
                &peer_self_id,
                &client_self_id,
                &sealed_key,
                minimum_fee,
            ))
            .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }
        EnclaveCall::GetMinimumFee => {
            serialize(&ENCLAVE.get_minimum_fee()).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }
        // Node-to-Node Attestation
        EnclaveCall::PeerInit(node_id) => {
            serialize(&ENCLAVE.peer_init(&node_id)).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }
        EnclaveCall::PeerAccept(auth_msg) => {
            serialize(&ENCLAVE.peer_accept(auth_msg)).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }
        EnclaveCall::PeerConnect(node_id, auth_msg) => {
            serialize(&ENCLAVE.peer_connect(&node_id, auth_msg))
                .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }
        EnclaveCall::PeerClose(session_id) => serialize(&ENCLAVE.peer_close(&session_id))
            .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?,
        // Node-to-Client Attestation
        EnclaveCall::ClientAccept(auth_msg) => serialize(&ENCLAVE.client_accept(auth_msg))
            .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?,
        EnclaveCall::ClientClose(channel_id) => serialize(&ENCLAVE.client_close(channel_id))
            .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?,
        EnclaveCall::ClientDiscardMessage(msg) => serialize(&ENCLAVE.client_discard_message(msg))
            .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?,
        // Report Caching
        EnclaveCall::GetIdentity => {
            serialize(&ENCLAVE.get_identity()).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }
        EnclaveCall::GetSigner => {
            serialize(&ENCLAVE.get_signer()).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }
        EnclaveCall::GetFeeRecipient => {
            serialize(&ENCLAVE.get_fee_recipient()).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
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
        // Transactions
        EnclaveCall::ClientTxPropose(msg) => serialize(&ENCLAVE.client_tx_propose(msg))
            .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?,
        EnclaveCall::PeerTxPropose(msg) => {
            serialize(&ENCLAVE.peer_tx_propose(msg)).or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }
        EnclaveCall::TxIsWellFormed(locally_encrypted_tx, block_index, proofs) => {
            serialize(&ENCLAVE.tx_is_well_formed(locally_encrypted_tx, block_index, proofs))
                .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }
        EnclaveCall::TxsForPeer(txs, aad, peer) => {
            serialize(&ENCLAVE.txs_for_peer(&txs, &aad, &peer))
                .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }

        EnclaveCall::FormBlock(parent_block, encrypted_txs_with_proofs) => {
            serialize(&ENCLAVE.form_block(&parent_block, &encrypted_txs_with_proofs))
                .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))?
        }
    };

    Ok(outdata)
}

/// The entry point implementation for consensus_enclave_api
///
/// See mc_consensus_enclave_api::mobileenclave() declaration for more
/// information
#[no_mangle]
pub extern "C" fn mobileenclave_call(
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
