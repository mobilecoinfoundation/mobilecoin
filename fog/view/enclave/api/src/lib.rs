// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Defines a trait, and a serializable structure representing an RPC call,
//! for the API the view server uses to talk to the view enclave

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;
use core::result::Result as StdResult;
use displaydoc::Display;
use mc_attest_core::{Quote, Report, SgxError, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage,
    Error as AttestEnclaveError,
};
use mc_common::ResponderId;
use mc_crypto_keys::X25519Public;
use mc_fog_recovery_db_iface::FogUserEvent;
use mc_fog_types::ETxOutRecord;
use mc_sgx_compat::sync::PoisonError;
use mc_sgx_report_cache_api::ReportableEnclave;
use mc_sgx_types::{sgx_enclave_id_t, sgx_status_t};
use serde::{Deserialize, Serialize};

/// Untrusted data that is part of a view enclave query response.
#[derive(Serialize, Deserialize)]
pub struct UntrustedQueryResponse {
    /// User events.
    pub user_events: Vec<FogUserEvent>,

    /// The next value the user should use for start_from_user_event_id.
    pub next_start_from_user_event_id: i64,

    /// The number of blocks at the time that the request was evaluated.
    pub highest_processed_block_count: u64,

    /// The timestamp of the highest processed block at the time that the
    /// request was evaluated.
    pub highest_processed_block_signature_timestamp: u64,

    /// The index of the last known block, which can be obtained by calculating
    /// last_known_block_count - 1. We don't store the index but instead store a
    /// count so that we have a way of representing no known block (0).
    pub last_known_block_count: u64,

    /// The cumulative txo count of the last known block.
    pub last_known_block_cumulative_txo_count: u64,
}

/// Represents a serialized request for the view enclave to service
#[derive(Serialize, Deserialize)]
pub enum ViewEnclaveRequest {
    /// The enclave eid, and the AKE responder id
    Init(ViewEnclaveInitParams),

    /// Ake related
    /// Get the public identity assoicated to the enclave, for AKE
    GetIdentity,

    /// Get a new report
    NewEReport(TargetInfo),

    /// Verify a quote
    /// The report part should be a quoting enclave report
    VerifyQuote(Quote, Report),

    /// Verify an IAS report, and cache it if it is accepted
    VerifyIasReport(VerificationReport),

    /// Get the cached verification report if any
    GetIasReport,

    // View-enclave specific
    /// Accept a client connection
    ClientAccept(ClientAuthRequest),
    /// Close a client connection
    ClientClose(ClientSession),
    /// An encrypted fog_types::view::QueryRequest
    /// Respond with fog_types::view::QueryResponse
    Query(EnclaveMessage<ClientSession>, UntrustedQueryResponse),
    /// Request from untrusted to add encrypted tx out records to ORAM
    AddRecords(Vec<ETxOutRecord>),
}

/// The parameters needed to initialize the view enclave
/// TODO: Make this prost compatible
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ViewEnclaveInitParams {
    /// The sgx_enclave_id_t for this enclave. This is needed to pass to some
    /// OCALL's back to untrusted as an id for the enclave making the call.
    pub eid: sgx_enclave_id_t,
    /// The responder id for this enclave to use for client connections.
    pub self_client_id: ResponderId,
    /// The desired capacity of the store of records
    pub desired_capacity: u64,
}

/// The API for the view enclave
pub trait ViewEnclaveApi: ReportableEnclave {
    /// Perform one-time initialization upon enclave startup.
    fn init(&self, params: ViewEnclaveInitParams) -> Result<()>;

    //
    // AKE related
    //

    /// Retrieve the public identity of the enclave.
    fn get_identity(&self) -> Result<X25519Public>;

    //
    // View-enclave specific
    //

    // CLIENT-FACING METHODS

    /// Accept an inbound authentication request
    fn client_accept(&self, req: ClientAuthRequest) -> Result<(ClientAuthResponse, ClientSession)>;

    /// Destroy a peer association
    fn client_close(&self, channel_id: ClientSession) -> Result<()>;

    /// Service a user's encrypted QueryRequest
    fn query(
        &self,
        payload: EnclaveMessage<ClientSession>,
        untrusted_query_response: UntrustedQueryResponse,
    ) -> Result<Vec<u8>>;

    /// SERVER-FACING

    /// Add encrypted tx out records from the fog recovery db to the view
    /// enclave's ORAM
    fn add_records(&self, records: Vec<ETxOutRecord>) -> Result<()>;
}

/// Helper trait which reduces boiler-plate in untrusted side
/// The trusted object which implements the above api usually cannot implement
/// Clone, Send, Sync, etc., but the untrusted side can and usually having a
/// "handle to an enclave" is what is most useful for a webserver.
/// This marker trait can be implemented for the untrusted-side representation
/// of the enclave.
pub trait ViewEnclaveProxy: ViewEnclaveApi + Clone + Send + Sync + 'static {}

impl<T> ViewEnclaveProxy for T where T: ViewEnclaveApi + Clone + Send + Sync + 'static {}

// Error

/// A generic result type for enclave calls
pub type Result<T> = StdResult<T, Error>;

/// An error when something goes wrong with adding a record
#[derive(Serialize, Deserialize, Debug, Display, Clone)]
pub enum AddRecordsError {
    /// Key was wrong size
    KeyWrongSize,
    /// Key was rejected
    KeyRejected,
    /// Value was too large
    ValueTooLarge,
    /// Value was the wrong size
    ValueWrongSize,
    /// Map Overflowed: len = {0}, capacity = {1}
    MapOverflow(u64, u64),
}

/// An error returned by the view enclave
#[derive(Serialize, Deserialize, Debug, Display, Clone)]
pub enum Error {
    /// Sgx error: {0}
    Sgx(SgxError),
    /// Serde encode error
    SerdeEncode,
    /// Serde decode error
    SerdeDecode,
    /// Prost encode error
    ProstEncode,
    /// Prost decode error
    ProstDecode,
    /// Attest enclave error: {0}
    AttestEnclave(AttestEnclaveError),
    /// Add Records error: {0}
    AddRecords(AddRecordsError),
    /// An panic occurred on another thread
    Poison,
    /// Enclave not initialized
    EnclaveNotInitialized,
}

impl From<SgxError> for Error {
    fn from(src: SgxError) -> Self {
        Self::Sgx(src)
    }
}

impl From<sgx_status_t> for Error {
    fn from(src: sgx_status_t) -> Self {
        Self::Sgx(src.into())
    }
}

impl From<mc_util_serial::encode::Error> for Error {
    fn from(_: mc_util_serial::encode::Error) -> Self {
        Self::SerdeEncode
    }
}

impl From<mc_util_serial::decode::Error> for Error {
    fn from(_: mc_util_serial::decode::Error) -> Self {
        Self::SerdeDecode
    }
}

impl From<mc_util_serial::EncodeError> for Error {
    fn from(_: mc_util_serial::EncodeError) -> Self {
        Self::ProstEncode
    }
}

impl From<mc_util_serial::DecodeError> for Error {
    fn from(_: mc_util_serial::DecodeError) -> Self {
        Self::ProstDecode
    }
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_src: PoisonError<T>) -> Self {
        Error::Poison
    }
}

impl From<AttestEnclaveError> for Error {
    fn from(src: AttestEnclaveError) -> Self {
        Error::AttestEnclave(src)
    }
}

impl From<AddRecordsError> for Error {
    fn from(src: AddRecordsError) -> Self {
        Error::AddRecords(src)
    }
}
