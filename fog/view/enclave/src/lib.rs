// Copyright (c) 2018-2021 The MobileCoin Foundation

//! View Enclave Application-side Proxy object.

#![deny(missing_docs)]

extern crate mc_fog_ocall_oram_storage_untrusted;

use std::{path, result::Result as StdResult, sync::Arc};

use mc_attest_core::{
    IasNonce, Quote, QuoteNonce, Report, SgxError, TargetInfo, VerificationReport, DEBUG_ENCLAVE,
};
use mc_attest_enclave_api::{ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage};
use mc_common::{logger::Logger, ResponderId};
use mc_crypto_keys::X25519Public;
use mc_enclave_boundary::untrusted::make_variable_length_ecall;
use mc_fog_types::ETxOutRecord;
use mc_fog_view_enclave_api::UntrustedQueryResponse;
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};
use mc_sgx_types::{sgx_attributes_t, sgx_enclave_id_t, sgx_launch_token_t, sgx_misc_attribute_t};
use mc_sgx_urts::SgxEnclave;

pub use mc_fog_view_enclave_api::{
    Error, Result, ViewEnclaveApi, ViewEnclaveInitParams, ViewEnclaveProxy, ViewEnclaveRequest,
};

mod ecall;

/// The default filename of the fog view's SGX enclave binary.
pub const ENCLAVE_FILE: &str = "libview-enclave.signed.so";

/// A clone-able handle to a ViewEnclave suitable for use in servers
#[derive(Clone)]
pub struct SgxViewEnclave {
    enclave: Arc<SgxEnclave>,
    logger: Logger,
}

impl SgxViewEnclave {
    /// Create a new sgx view enclave
    ///
    /// Arguments:
    /// * enclave_path: The path to the signed enclave .so file
    /// * client_responder_id: The responder_id to be used when connecting to
    ///   clients
    /// * db: The recovery db to read data from. This is used when servicing
    ///   seeds requests
    /// * desired_capacity: The desired capacity for ETxOutRecords in the
    ///   oblivious map. Must be a power of two. Actual capacity will be ~70% of
    ///   this. Memory utilization will be about 256 bytes * this + some
    ///   overhead
    /// * logger: Logger to use
    pub fn new(
        enclave_path: path::PathBuf,
        client_responder_id: ResponderId,
        desired_capacity: u64,
        logger: Logger,
    ) -> Self {
        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: i32 = 0;
        // FIXME: this must be filled in from the build.rs
        let mut misc_attr = sgx_misc_attribute_t {
            secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
            misc_select: 0,
        };

        let result = Self {
            enclave: Arc::new(
                SgxEnclave::create(
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
                }),
            ),
            logger: logger.clone(),
        };

        // Do sgx_enclave id and ake init
        let eid = result.enclave.geteid();
        let params = ViewEnclaveInitParams {
            eid,
            self_client_id: client_responder_id,
            desired_capacity,
        };

        result.init(params).expect("Could not initialize enclave");

        result
    }

    fn eid(&self) -> sgx_enclave_id_t {
        self.enclave.geteid()
    }

    /// Takes serialized data, and fires to the corresponding ECALL.
    fn enclave_call(&self, inbuf: &[u8]) -> StdResult<Vec<u8>, SgxError> {
        Ok(make_variable_length_ecall(
            self.eid(),
            ecall::viewenclave_call,
            &inbuf,
        )?)
    }
}

impl ReportableEnclave for SgxViewEnclave {
    fn new_ereport(&self, qe_info: TargetInfo) -> ReportableEnclaveResult<(Report, QuoteNonce)> {
        let inbuf = mc_util_serial::serialize(&ViewEnclaveRequest::NewEReport(qe_info))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn verify_quote(&self, quote: Quote, qe_report: Report) -> ReportableEnclaveResult<IasNonce> {
        let inbuf = mc_util_serial::serialize(&ViewEnclaveRequest::VerifyQuote(quote, qe_report))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn verify_ias_report(&self, ias_report: VerificationReport) -> ReportableEnclaveResult<()> {
        let inbuf = mc_util_serial::serialize(&ViewEnclaveRequest::VerifyIasReport(ias_report))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_ias_report(&self) -> ReportableEnclaveResult<VerificationReport> {
        let inbuf = mc_util_serial::serialize(&ViewEnclaveRequest::GetIasReport)?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }
}

impl ViewEnclaveApi for SgxViewEnclave {
    fn init(&self, params: ViewEnclaveInitParams) -> Result<()> {
        let inbuf = mc_util_serial::serialize(&ViewEnclaveRequest::Init(params))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_identity(&self) -> Result<X25519Public> {
        let inbuf = mc_util_serial::serialize(&ViewEnclaveRequest::GetIdentity)?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn client_accept(&self, req: ClientAuthRequest) -> Result<(ClientAuthResponse, ClientSession)> {
        let inbuf = mc_util_serial::serialize(&ViewEnclaveRequest::ClientAccept(req))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn client_close(&self, channel_id: ClientSession) -> Result<()> {
        let inbuf = mc_util_serial::serialize(&ViewEnclaveRequest::ClientClose(channel_id))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn query(
        &self,
        payload: EnclaveMessage<ClientSession>,
        untrusted_query_response: UntrustedQueryResponse,
    ) -> Result<Vec<u8>> {
        let inbuf = mc_util_serial::serialize(&ViewEnclaveRequest::Query(
            payload,
            untrusted_query_response,
        ))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn add_records(&self, records: Vec<ETxOutRecord>) -> Result<()> {
        let inbuf = mc_util_serial::serialize(&ViewEnclaveRequest::AddRecords(records))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }
}
