// Copyright (c) 2018-2021 The MobileCoin Foundation

//! MobileCoin Fog Ingest SGX Enclave Untrusted Proxy

#![deny(missing_docs)]

extern crate mc_fog_ocall_oram_storage_untrusted;

pub use mc_fog_ingest_enclave_api::{
    Error, IngestEnclave, IngestEnclaveInitParams, IngestEnclaveProxy, Result, SealedIngestKey,
};

use mc_attest_core::{
    IasNonce, Quote, QuoteNonce, Report, SgxError, TargetInfo, VerificationReport, DEBUG_ENCLAVE,
};
use mc_attest_enclave_api::{EnclaveMessage, PeerAuthRequest, PeerAuthResponse, PeerSession};
use mc_common::ResponderId;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic, X25519Public};
use mc_enclave_boundary::untrusted::make_variable_length_ecall;
use mc_fog_ingest_enclave_api::EnclaveCall;
use mc_fog_kex_rng::KexRngPubkey;
use mc_fog_recovery_db_iface::ETxOutRecord;
use mc_fog_types::ingest::TxsForIngest;
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};
use mc_sgx_types::{
    sgx_attributes_t, sgx_enclave_id_t, sgx_launch_token_t, sgx_misc_attribute_t, sgx_status_t,
};
use mc_sgx_urts::SgxEnclave;
use std::{path, result::Result as StdResult, sync::Arc};

/// The default filename of the fog ingest's SGX enclave binary.
pub const ENCLAVE_FILE: &str = "libingest-enclave.signed.so";

/// A handle to an ingest enclave, on the untrusted side
#[derive(Clone)]
pub struct IngestSgxEnclave {
    // The enclave id, this can be retrieved from SgxEnclave object,
    // but it is cached here because it is needed whenever we make an ECALL.
    eid: sgx_enclave_id_t,
    // Hold a reference counter to the enclave to prevent destruction.
    // This is a proxy object, its lifetime is not in lock-step with the
    // actual enclave.
    enclave: Arc<SgxEnclave>,
}

impl IngestSgxEnclave {
    /// Create a new ingest enclave
    ///
    /// Arguments:
    /// - enclave_path: the full path to the signed enclave binary
    /// - peer_self_id: The responder_id to use with AKE when peering with other
    ///   ingest enclaves
    /// - sealed_key: A sealed fog private key which we backed up earlier, to
    ///   restore now in SGX. If omitted then the enclave creates a new private
    ///   key randomly.
    /// - omap_capacity: The capacity of the Oblivious Map that this enclave
    ///   will create. Total memory usage should be about 64 * this value, +
    ///   some overhead, and about 70% of the capacity won't be usable due to
    ///   hash table overflow. So the *number of users* the enclave can support
    ///   is about 70% times this.
    ///
    /// Returns:
    /// - The enclave proxy object, and the sealed ingest private key.
    pub fn new(
        enclave_path: path::PathBuf,
        peer_self_id: &ResponderId,
        sealed_key: &Option<SealedIngestKey>,
        omap_capacity: u64,
    ) -> IngestSgxEnclave {
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
        .unwrap_or_else(|err| {
            panic!(
                "SgxEnclave::create(file_name={:?}, debug={}) failed: {:?}",
                &enclave_path, DEBUG_ENCLAVE as i32, err
            )
        });
        let sgx_enclave = IngestSgxEnclave {
            eid: enclave.geteid(),
            enclave: Arc::new(enclave),
        };

        let params = IngestEnclaveInitParams {
            responder_id: peer_self_id.clone(),
            sealed_key: sealed_key.clone(),
            desired_capacity: omap_capacity,
        };

        sgx_enclave
            .enclave_init(params)
            .expect("enclave_init failed");

        sgx_enclave
    }

    /// Takes serialized data, and fires to the corresponding ECALL.
    fn enclave_call(&self, inbuf: &[u8]) -> StdResult<Vec<u8>, SgxError> {
        Ok(make_variable_length_ecall(
            self.eid,
            ingest_enclave_call,
            &inbuf,
        )?)
    }
}

impl ReportableEnclave for IngestSgxEnclave {
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
impl IngestEnclave for IngestSgxEnclave {
    fn enclave_init(&self, params: IngestEnclaveInitParams) -> Result<()> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::EnclaveInit(params))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn new_keys(&self) -> Result<()> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::NewKeys)?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn new_egress_key(&self) -> Result<()> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::NewEgressKey)?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_ingress_pubkey(&self) -> Result<RistrettoPublic> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::GetIngressPubkey)?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_sealed_ingress_private_key(
        &self,
    ) -> Result<(SealedIngestKey, CompressedRistrettoPublic)> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::GetSealedIngressPrivateKey)?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_ingress_private_key(
        &self,
        peer: PeerSession,
    ) -> Result<(EnclaveMessage<PeerSession>, CompressedRistrettoPublic)> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::GetIngressPrivateKey(peer))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn set_ingress_private_key(
        &self,
        msg: EnclaveMessage<PeerSession>,
    ) -> Result<(RistrettoPublic, SealedIngestKey)> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::SetIngressPrivateKey(msg))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_kex_rng_pubkey(&self) -> Result<KexRngPubkey> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::GetKexRngPubkey)?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn ingest_txs(&self, chunk: TxsForIngest) -> Result<(Vec<ETxOutRecord>, Option<KexRngPubkey>)> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::IngestTxs(chunk))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_identity(&self) -> Result<X25519Public> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::GetIdentity)?;
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
    /// in two parts. The first part is the literal `enclave_api()` C function,
    /// which lives in the untrusted code. The second part is a corresponding
    /// function that will run inside the enclave as an ECALL. The generated
    /// untrusted function will call the generated trusted function. This
    /// implicitly depends on a real function inside the enclave that is
    /// similar, but not identical, in that it does not include the `eid`
    /// parameter. As a result, the call stack will look something like
    /// this:
    ///
    ///  1. Application Code
    ///  2. Untrusted generated_enclave_api(eid, retval, inbuf, ...) function
    ///  3. Trusted, generated_enclave_api(inbuf, ...) ECALL
    ///  4. Target enclave_api(inbuf, ...) method inside rust in the
    ///     enclave.
    pub fn ingest_enclave_call(
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
