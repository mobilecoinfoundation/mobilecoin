// Copyright (c) 2018-2021 The MobileCoin Foundation

//! MobileCoin Fog Ledger SGX Enclave Untrusted Proxy

#![deny(missing_docs)]

extern crate mc_fog_ocall_oram_storage_untrusted;

pub use mc_fog_ledger_enclave_api::{
    CheckKeyImagesResponse, EnclaveCall, Error, GetOutputsResponse, KeyImageData, KeyImageResult,
    KeyImageResultCode, LedgerEnclave, LedgerEnclaveProxy, OutputContext, OutputResult, Result,
};

use mc_attest_core::{
    IasNonce, Quote, QuoteNonce, Report, SgxError, TargetInfo, VerificationReport, DEBUG_ENCLAVE,
};
use mc_attest_enclave_api::{ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage};
use mc_common::{logger::Logger, ResponderId};
use mc_crypto_keys::X25519Public;
use mc_enclave_boundary::untrusted::make_variable_length_ecall;
use mc_fog_ledger_enclave_api::UntrustedKeyImageQueryResponse;
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};
use mc_sgx_types::{
    sgx_attributes_t, sgx_enclave_id_t, sgx_launch_token_t, sgx_misc_attribute_t, sgx_status_t,
};
use mc_sgx_urts::SgxEnclave;
use std::{path, result::Result as StdResult, sync::Arc};

/// The default filename of the fog ledger's SGX enclave binary.
pub const ENCLAVE_FILE: &str = "libledger-enclave.signed.so";

/// A clone-able handle to the enclave suitable for use in servers
#[derive(Clone)]
pub struct LedgerSgxEnclave {
    eid: sgx_enclave_id_t,
    // Hold a reference counter to the enclave to prevent destruction.
    enclave: Arc<SgxEnclave>,
    logger: Logger,
}

impl ReportableEnclave for LedgerSgxEnclave {
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

impl LedgerSgxEnclave {
    /// Create a new sgx ledger enclave
    ///
    /// Arguments:
    /// * enclave_path: The path to the signed enclave .so file
    /// * self_id: The responder_id to be used when client is connecting to us
    /// * desired_capacity: The desired capacity in the oblivious map. Must be a
    ///   power of two. Actual capacity will be ~70% of this. Memory utilization
    ///   will be about 256 bytes * this + some overhead
    /// * logger: Logger to use
    pub fn new(
        enclave_path: path::PathBuf,
        self_id: &ResponderId,
        desired_capacity: u64,
        logger: Logger,
    ) -> LedgerSgxEnclave {
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
        .unwrap_or_else(|e| {
            panic!(
                "SgxEnclave::create(file_name={:?}, debug={}) failed: {:?}",
                &enclave_path, DEBUG_ENCLAVE as i32, e
            )
        });
        let sgx_enclave = LedgerSgxEnclave {
            eid: enclave.geteid(),
            enclave: Arc::new(enclave),
            logger: logger.clone(),
        };

        sgx_enclave
            .enclave_init(self_id, desired_capacity)
            .unwrap_or_else(|e| panic!("enclave_init({}) failed: {:?}", self_id, e));

        sgx_enclave
    }

    /// Takes serialized data, and fires to the corresponding ECALL.
    fn enclave_call(&self, inbuf: &[u8]) -> StdResult<Vec<u8>, SgxError> {
        Ok(make_variable_length_ecall(
            self.eid,
            ledger_enclave_call,
            &inbuf,
        )?)
    }
}

/// Proxy API for talking to the corresponding implementation inside the
/// enclave.
impl LedgerEnclave for LedgerSgxEnclave {
    fn enclave_init(&self, self_id: &ResponderId, desired_capacity: u64) -> Result<()> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::EnclaveInit(
            self_id.clone(),
            desired_capacity,
        ))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_identity(&self) -> Result<X25519Public> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::GetIdentity)?;
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

    fn get_outputs(&self, msg: EnclaveMessage<ClientSession>) -> Result<OutputContext> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::GetOutputs(msg))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_outputs_data(
        &self,
        resp: GetOutputsResponse,
        client: ClientSession,
    ) -> Result<EnclaveMessage<ClientSession>> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::GetOutputsData(resp, client))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn check_key_images(
        &self,
        msg: EnclaveMessage<ClientSession>,
        untrusted_keyimagequery_response: UntrustedKeyImageQueryResponse,
    ) -> Result<Vec<u8>> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::CheckKeyImages(
            msg,
            untrusted_keyimagequery_response,
        ))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    // Add a key image data to the oram in the key image
    fn add_key_image_data(&self, records: Vec<KeyImageData>) -> Result<()> {
        let inbuf = mc_util_serial::serialize(&EnclaveCall::AddKeyImageData(records))?;
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
    pub fn ledger_enclave_call(
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
