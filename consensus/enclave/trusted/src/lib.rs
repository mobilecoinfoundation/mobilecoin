// Copyright (c) 2018-2022 The MobileCoin Foundation

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
    static ref RETRY_BUFFER: RetryBuffer = RetryBuffer::new(ecall_dispatcher);

    /// Storage for the business logic / implementation state
    static ref ENCLAVE: SgxConsensusEnclave = SgxConsensusEnclave::new(mc_sgx_slog::default_logger());
}

/// Dispatch ecalls with the unified signature
pub fn ecall_dispatcher(inbuf: &[u8]) -> Result<Vec<u8>, sgx_status_t> {
    // Figure out what we're trying to do
    let call_details: EnclaveCall =
        deserialize(inbuf).or(Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER))?;

    // And actually do it
    match call_details {
        // Utility methods
        EnclaveCall::EnclaveInit(peer_self_id, client_self_id, sealed_key, blockchain_config) => {
            serialize(&ENCLAVE.enclave_init(
                &peer_self_id,
                &client_self_id,
                &sealed_key,
                blockchain_config,
            ))
        }
        EnclaveCall::GetMinimumFee(token_id) => serialize(&ENCLAVE.get_minimum_fee(&token_id)),
        // Node-to-Node Attestation
        EnclaveCall::PeerInit(node_id) => serialize(&ENCLAVE.peer_init(&node_id)),
        EnclaveCall::PeerAccept(auth_msg) => serialize(&ENCLAVE.peer_accept(auth_msg)),
        EnclaveCall::PeerConnect(node_id, auth_msg) => {
            serialize(&ENCLAVE.peer_connect(&node_id, auth_msg))
        }
        EnclaveCall::PeerClose(session_id) => serialize(&ENCLAVE.peer_close(&session_id)),
        // Node-to-Client Attestation
        EnclaveCall::ClientAccept(auth_msg) => serialize(&ENCLAVE.client_accept(auth_msg)),
        EnclaveCall::ClientClose(channel_id) => serialize(&ENCLAVE.client_close(channel_id)),
        EnclaveCall::ClientDiscardMessage(msg) => serialize(&ENCLAVE.client_discard_message(msg)),
        // Keys
        EnclaveCall::GetIdentity => serialize(&ENCLAVE.get_identity()),
        EnclaveCall::GetSigner => serialize(&ENCLAVE.get_signer()),
        EnclaveCall::GetFeeRecipient => serialize(&ENCLAVE.get_fee_recipient()),
        EnclaveCall::GetMintingTrustRoot => serialize(&ENCLAVE.get_minting_trust_root()),
        // Report Caching
        EnclaveCall::NewEreport(qe_info) => serialize(&ENCLAVE.new_ereport(qe_info)),
        EnclaveCall::VerifyQuote(quote, qe_report) => {
            serialize(&ENCLAVE.verify_quote(quote, qe_report))
        }
        EnclaveCall::VerifyReport(ias_report) => serialize(&ENCLAVE.verify_ias_report(ias_report)),
        EnclaveCall::GetReport => serialize(&ENCLAVE.get_ias_report()),
        // Transactions
        EnclaveCall::ClientTxPropose(msg) => serialize(&ENCLAVE.client_tx_propose(msg)),
        EnclaveCall::PeerTxPropose(msg) => serialize(&ENCLAVE.peer_tx_propose(msg)),
        EnclaveCall::TxIsWellFormed(locally_encrypted_tx, block_index, proofs) => {
            serialize(&ENCLAVE.tx_is_well_formed(locally_encrypted_tx, block_index, proofs))
        }
        EnclaveCall::TxsForPeer(txs, aad, peer) => {
            serialize(&ENCLAVE.txs_for_peer(&txs, &aad, &peer))
        }
        EnclaveCall::FormBlock(parent_block, inputs, root_element) => {
            serialize(&ENCLAVE.form_block(&parent_block, inputs, &root_element))
        }
    }
    .or(Err(sgx_status_t::SGX_ERROR_UNEXPECTED))
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
