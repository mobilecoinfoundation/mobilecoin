// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The Consensus Service SGX Enclave Proxy

pub use mc_consensus_enclave_api::{
    ConsensusEnclave, ConsensusEnclaveProxy, EnclaveCall, Error, FeePublicKey, LocallyEncryptedTx,
    Result, TxContext, WellFormedEncryptedTx, WellFormedTxContext,
};

use mc_attest_core::{
    IasNonce, Quote, QuoteNonce, Report, SgxError, TargetInfo, VerificationReport, DEBUG_ENCLAVE,
};
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage, PeerAuthRequest,
    PeerAuthResponse, PeerSession,
};
use mc_common::ResponderId;
use mc_crypto_keys::{Ed25519Public, X25519Public};
use mc_enclave_boundary::untrusted::make_variable_length_ecall;
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};
use mc_sgx_types::{sgx_enclave_id_t, sgx_status_t, *};
use mc_sgx_urts::SgxEnclave;
use mc_transaction_core::{tx::TxOutMembershipProof, Block, BlockContents, BlockSignature};
use std::{path, result::Result as StdResult, sync::Arc};

/// The default filename of the consensus service's SGX enclave binary.
pub const ENCLAVE_FILE: &str = "libconsensus-enclave.signed.so";

#[derive(Clone)]
pub struct ConsensusServiceSgxEnclave {
    /// Hold a reference counter to the enclave to prevent destruction,
    /// this object is a handle to an enclave rather than having its lifetime
    /// tied to the actual enclave.
    enclave: Arc<SgxEnclave>,
}

impl ConsensusServiceSgxEnclave {
    pub fn new(
        enclave_path: path::PathBuf,
        self_peer_id: &ResponderId,
        self_client_id: &ResponderId,
        sealed_key: &Option<SealedBlockSigningKey>,
        minimum_fee: Option<u64>,
    ) -> (
        ConsensusServiceSgxEnclave,
        SealedBlockSigningKey,
        Vec<String>,
    ) {
        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: i32 = 0;
        // FIXME: this must be filled in from the build.rs
        let mut misc_attr = sgx_misc_attribute_t {
            secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
            misc_select: 0,
        };
        let enclave = SgxEnclave::create(
            &enclave_path,
            DEBUG_ENCLAVE as i32,
            &mut launch_token,
            &mut launch_token_updated,
            &mut misc_attr,
        )
        .expect("Could not create consensus enclave");

        let sgx_enclave = ConsensusServiceSgxEnclave {
            enclave: Arc::new(enclave),
        };

        let (sealed_key, features) = sgx_enclave
            .enclave_init(self_peer_id, self_client_id, &sealed_key, minimum_fee)
            .expect("enclave_init failed");

        (sgx_enclave, sealed_key, features)
    }

    /// Takes serialized data, and fires to the corresponding ECALL.
    fn enclave_call(&self, inbuf: &[u8]) -> StdResult<Vec<u8>, SgxError> {
        Ok(make_variable_length_ecall(
            self.enclave.geteid(),
            mobileenclave_call,
            &inbuf,
        )?)
    }
}

pub type SealedBlockSigningKey = Vec<u8>;

impl ReportableEnclave for ConsensusServiceSgxEnclave {
    fn new_ereport(&self, qe_info: TargetInfo) -> ReportableEnclaveResult<(Report, QuoteNonce)> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::NewEreport(qe_info))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn verify_quote(&self, quote: Quote, qe_report: Report) -> ReportableEnclaveResult<IasNonce> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::VerifyQuote(quote, qe_report))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn verify_ias_report(&self, ias_report: VerificationReport) -> ReportableEnclaveResult<()> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::VerifyReport(ias_report))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_ias_report(&self) -> ReportableEnclaveResult<VerificationReport> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::GetReport)?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }
}

/// Proxy API for talking to the corresponding implementation inside the
/// enclave.
impl ConsensusEnclave for ConsensusServiceSgxEnclave {
    fn enclave_init(
        &self,
        self_peer_id: &ResponderId,
        self_client_id: &ResponderId,
        sealed_key: &Option<SealedBlockSigningKey>,
        minimum_fee: Option<u64>,
    ) -> Result<(SealedBlockSigningKey, Vec<String>)> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::EnclaveInit(
            self_peer_id.clone(),
            self_client_id.clone(),
            sealed_key.clone(),
            minimum_fee,
        ))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_minimum_fee(&self) -> Result<u64> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::GetMinimumFee)?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_identity(&self) -> Result<X25519Public> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::GetIdentity)?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_signer(&self) -> Result<Ed25519Public> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::GetSigner)?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_fee_recipient(&self) -> Result<FeePublicKey> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::GetFeeRecipient)?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn client_accept(&self, req: ClientAuthRequest) -> Result<(ClientAuthResponse, ClientSession)> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::ClientAccept(req))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn client_close(&self, channel_id: ClientSession) -> Result<()> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::ClientClose(channel_id))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn client_discard_message(&self, msg: EnclaveMessage<ClientSession>) -> Result<()> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::ClientDiscardMessage(msg))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn peer_init(&self, peer_id: &ResponderId) -> Result<PeerAuthRequest> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::PeerInit(peer_id.clone()))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn peer_accept(&self, req: PeerAuthRequest) -> Result<(PeerAuthResponse, PeerSession)> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::PeerAccept(req))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn peer_connect(
        &self,
        peer_id: &ResponderId,
        msg: PeerAuthResponse,
    ) -> Result<(PeerSession, VerificationReport)> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::PeerConnect(peer_id.clone(), msg))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn peer_close(&self, session_id: &PeerSession) -> Result<()> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::PeerClose(session_id.clone()))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn client_tx_propose(&self, msg: EnclaveMessage<ClientSession>) -> Result<TxContext> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::ClientTxPropose(msg))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn peer_tx_propose(&self, msg: EnclaveMessage<PeerSession>) -> Result<Vec<TxContext>> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::PeerTxPropose(msg))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn tx_is_well_formed(
        &self,
        locally_encrypted_tx: LocallyEncryptedTx,
        block_index: u64,
        proofs: Vec<TxOutMembershipProof>,
    ) -> Result<(WellFormedEncryptedTx, WellFormedTxContext)> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::TxIsWellFormed(
            locally_encrypted_tx,
            block_index,
            proofs,
        ))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn txs_for_peer(
        &self,
        encrypted_txs: &[WellFormedEncryptedTx],
        aad: &[u8],
        peer: &PeerSession,
    ) -> Result<EnclaveMessage<PeerSession>> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::TxsForPeer(
            encrypted_txs.to_vec(),
            aad.to_vec(),
            peer.clone(),
        ))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn form_block(
        &self,
        parent_block: &Block,
        txs_with_proofs: &[(WellFormedEncryptedTx, Vec<TxOutMembershipProof>)],
    ) -> Result<(Block, BlockContents, BlockSignature)> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::FormBlock(
            parent_block.clone(),
            txs_with_proofs.to_vec(),
        ))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }
}

extern "C" {
    /// Unified Enclave ECALL declaration.
    ///
    /// Callers should initialize `outbuf_used` and `outbuf_retry_id`
    /// to zero before calling the first time. In the event the
    /// output buffer is not large enough to hold the serialized
    /// result, the enclave must cache the output buffer keyed by
    /// a numeric ID, set the `outbuf_used` to the required size,
    /// update the `outbuf_retry_id` to the numeric ID, and return
    /// `sgx_status_t::SGX_ERROR_OUT_OF_MEMORY`.
    ///
    /// When callers see that return value, they must resize their
    /// output buffer and repeat the call with the `outbuf_retry_id`
    /// set to the value returned by the enclave. The enclave will
    /// copy the cached output into the newly resized outbuf, set
    /// `outbuf_used` appropriately, reset `outbuf_retry_id` to
    /// zero, and return `sgx_status_t::SGX_STATUS_SUCCESS`, indicating
    /// the underlying ECALL was successful.
    ///
    /// Other sgx_status_t values are not similarly overloaded.
    ///
    /// The implementation of this method is auto-generated by edger8r,
    /// in two parts. The first part is the literal `consensus_enclave_api()` C
    /// function, which lives in the untrusted code. The second part is a
    /// corresponding function that will run inside the enclave as an ECALL.
    /// The generated untrusted function will call the generated trusted
    /// function. This implicitly depends on a real function inside the
    /// enclave that is similar, but not identical, in that it does not
    /// include the `eid` parameter. As a result, the call stack will look
    /// something like this:
    ///
    ///  1. Application Code
    ///  2. Untrusted generated_enclave_api(eid, retval, inbuf, ...) function
    ///  3. Trusted, generated_enclave_api(inbuf, ...) ECALL
    ///  4. Target consensus_enclave_api(inbuf, ...) method inside rust in the
    ///     enclave.
    pub fn mobileenclave_call(
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

// Get the "handle" marker trait as well
impl ConsensusEnclaveProxy for ConsensusServiceSgxEnclave {}
