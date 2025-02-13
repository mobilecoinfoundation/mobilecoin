// Copyright (c) 2018-2022 The MobileCoin Foundation

//! APIs for MobileCoin Ledger Service Enclave

#![no_std]
#![deny(missing_docs)]
#![allow(clippy::result_large_err)]

extern crate alloc;

mod error;
mod messages;
pub use crate::{
    error::{AddRecordsError, Error},
    messages::{EnclaveCall, KeyImageData},
};
use alloc::{collections::BTreeMap, vec::Vec};
use core::result::Result as StdResult;
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage, NonceAuthRequest,
    NonceAuthResponse, NonceSession, SealedClientMessage,
};
use mc_common::ResponderId;
use mc_crypto_keys::X25519Public;
use mc_fog_types::common::BlockRange;
pub use mc_fog_types::ledger::{
    CheckKeyImagesResponse, GetOutputsResponse, KeyImageResult, KeyImageResultCode, OutputResult,
};
use mc_sgx_report_cache_api::ReportableEnclave;
use serde::{Deserialize, Serialize};

/// A generic result type for enclave calls
pub type Result<T> = StdResult<T, Error>;

/// An intermediate struct for holding data required to get outputs for the
/// client.
///
/// This is returned by `client_get_outputs` and allows untrusted to
/// gather data that will be encrypted for the client in `outputs_for_client`.
///
/// Key image check is now in ORAM, replacing untrusted
/// which was doing the check directly.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct OutputContext {
    /// The global txout indices being requested
    pub indexes: Vec<u64>,
    /// The common merkle-root block that all the proofs should share
    pub merkle_root_block: u64,
}

/// Enclave response to a query contains information known only to the enclave
/// (the check), but also some information only known outside the enclave, which
/// is injected when the enclave is called
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct UntrustedKeyImageQueryResponse {
    /// The number of blocks at the time that the request was evaluated.
    pub processed_block_range: BlockRange,

    /// The cumulative txo count of the last known block.
    pub last_known_block_cumulative_txo_count: u64,

    /// The latest value of block version in the blockchain
    pub latest_block_version: u32,

    /// The (max of) latest_block_version and mc_transaction_core::BLOCK_VERSION
    pub max_block_version: u32,
}

/// The API for interacting with a ledger node's enclave.
pub trait LedgerEnclave: ReportableEnclave {
    // UTILITY METHODS
    /// Perform one-time initialization upon enclave startup.
    fn enclave_init(&self, self_id: &ResponderId, desired_capacity: u64) -> Result<()>;

    /// Retrieve the public identity of the enclave.
    fn get_identity(&self) -> Result<X25519Public>;

    // CLIENT-FACING METHODS

    /// Accept an inbound authentication request
    fn client_accept(&self, req: ClientAuthRequest) -> Result<(ClientAuthResponse, ClientSession)>;

    /// Destroy a peer association
    fn client_close(&self, channel_id: ClientSession) -> Result<()>;

    /// Extract context data to be handed back to untrusted so that it could
    /// collect the information required.
    fn get_outputs(&self, msg: EnclaveMessage<ClientSession>) -> Result<OutputContext>;

    /// Encrypt outputs and proofs for the given client session, using the given
    /// authenticated data for the client.
    fn get_outputs_data(
        &self,
        response: GetOutputsResponse,
        client: ClientSession,
    ) -> Result<EnclaveMessage<ClientSession>>;

    /// Extract context data to be handed back to untrusted so that it could
    /// collect the information required.
    fn check_key_images(
        &self,
        msg: EnclaveMessage<ClientSession>,
        response: UntrustedKeyImageQueryResponse,
    ) -> Result<Vec<u8>>;

    /// Add a key image data to the oram Using thrm -rf targete key image
    fn add_key_image_data(&self, records: Vec<KeyImageData>) -> Result<()>;

    // LEDGER ROUTER / STORE SYSTEM

    /// Begin a connection to a Fog Ledger Store. The enclave calling this
    /// method, most likely a router, will act as a client to the Fog Ledger
    /// Store.
    fn ledger_store_init(&self, ledger_store_id: ResponderId) -> Result<NonceAuthRequest>;

    /// Called by a ledger store server to accept an incoming connection from a
    /// Fog Ledger Router instance acting as a frontend to the Ledger Store.
    fn frontend_accept(
        &self,
        auth_request: NonceAuthRequest,
    ) -> Result<(NonceAuthResponse, NonceSession)>;

    /// Complete the connection to a Fog Ledger Store that has accepted our
    /// NonceAuthRequest. This is meant to be called after the enclave has
    /// initialized and discovers a new Fog Ledger Store.
    fn ledger_store_connect(
        &self,
        ledger_store_id: ResponderId,
        ledger_store_auth_response: NonceAuthResponse,
    ) -> Result<()>;

    /// Check to see if a particular key image is present on this key image
    /// store. Used by the store server in a router/store system to respond
    /// to requests from a ledger router.
    fn check_key_image_store(
        &self,
        msg: EnclaveMessage<NonceSession>,
        response: UntrustedKeyImageQueryResponse,
    ) -> Result<EnclaveMessage<NonceSession>>;

    /// Decrypts a client query message and converts it into a
    /// SealedClientMessage which can be unsealed multiple times to
    /// construct the MultiKeyImageStoreRequest.
    fn decrypt_and_seal_query(
        &self,
        client_query: EnclaveMessage<ClientSession>,
    ) -> Result<SealedClientMessage>;

    /// Transforms a client query request into a list of query request data.
    ///
    /// The returned list is meant to be used to construct the
    /// MultiKeyImageStoreRequest, which is sent to each shard.
    fn create_multi_key_image_store_query_data(
        &self,
        sealed_query: SealedClientMessage,
    ) -> Result<Vec<EnclaveMessage<NonceSession>>>;

    /// Receives all of the shards' query responses and collates them into one
    /// query response for the client.
    fn collate_shard_query_responses(
        &self,
        sealed_query: SealedClientMessage,
        shard_query_responses: BTreeMap<ResponderId, EnclaveMessage<NonceSession>>,
    ) -> Result<EnclaveMessage<ClientSession>>;
}

/// Helper trait which reduces boiler-plate in untrusted side.
///
/// The trusted object which implements the above api usually cannot implement
/// Clone, Send, Sync, etc., but the untrusted side can and usually having a
/// "handle to an enclave" is what is most useful for a webserver.
/// This marker trait can be implemented for the untrusted-side representation
/// of the enclave.
pub trait LedgerEnclaveProxy: LedgerEnclave + Clone + Send + Sync + 'static {}

impl<T> LedgerEnclaveProxy for T where T: LedgerEnclave + Clone + Send + Sync + 'static {}
