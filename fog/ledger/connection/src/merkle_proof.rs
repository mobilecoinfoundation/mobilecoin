// Copyright (c) 2018-2022 The MobileCoin Foundation

use super::Error;
use displaydoc::Display;
use grpcio::{ChannelBuilder, Environment};
use mc_attestation_verifier::TrustedIdentity;
use mc_common::logger::{o, Logger};
use mc_fog_api::ledger_grpc::FogMerkleProofApiClient;
use mc_fog_enclave_connection::EnclaveConnection;
use mc_fog_types::ledger::{GetOutputsRequest, GetOutputsResponse, OutputResult};
use mc_fog_uri::FogLedgerUri;
use mc_transaction_core::tx::{TxOut, TxOutMembershipProof};
use mc_util_grpc::{ConnectionUriGrpcioChannel, GrpcRetryConfig};
use std::sync::Arc;

/// A high level object for making requests to the Fog Merkle Proof service.
pub struct FogMerkleProofGrpcClient {
    /// The attested connection
    conn: EnclaveConnection<FogLedgerUri, FogMerkleProofApiClient>,
    /// Grpc retry config
    grpc_retry_config: GrpcRetryConfig,
    /// Uri to connect to
    uri: FogLedgerUri,
}

impl FogMerkleProofGrpcClient {
    /// Create a new client object
    ///
    /// Arguments:
    /// * chain_id: The id of the network we expect to talk to. Ignored if
    ///   empty.
    /// * uri: The uri to connect to
    /// * grpc_retry_config: The retry policy to use for connection errors
    /// * identities: The identities that are allowed for attestation
    /// * env: The grpc environment to use (thread pool)
    /// * logger: for logging
    pub fn new(
        chain_id: String,
        uri: FogLedgerUri,
        grpc_retry_config: GrpcRetryConfig,
        identities: impl Into<Vec<TrustedIdentity>>,
        env: Arc<Environment>,
        logger: Logger,
    ) -> Self {
        let logger = logger.new(o!("mc.ledger.cxn" => uri.to_string()));

        let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&uri, &logger);

        let grpc_client = FogMerkleProofApiClient::new(ch);

        Self {
            conn: EnclaveConnection::new(chain_id, uri.clone(), grpc_client, identities, logger),
            grpc_retry_config,
            uri,
        }
    }

    /// Make a private request for membership proofs for given TxOuts
    pub fn get_outputs(
        &mut self,
        indices: Vec<u64>,
        merkle_root_block: u64,
    ) -> Result<GetOutputsResponse, Error> {
        let request = GetOutputsRequest {
            indices,
            merkle_root_block,
        };

        let retry_config = self.grpc_retry_config;

        let response: GetOutputsResponse = retry_config
            .retry(|| self.conn.retriable_encrypted_enclave_request(&request, &[]))
            .map_err(|err| Error::Connection(self.uri.clone(), err))?;

        Ok(response)
    }
}

/// An extension trait that adds a convenience method to check that status of an
/// output result.
pub trait OutputResultExtension {
    /// Check the status of an output query.
    /// A none status indicates that the result was not found
    /// An Error indicates that something went wrong resolving the query
    fn status(&self) -> Result<Option<(TxOut, TxOutMembershipProof)>, OutputError>;
}

impl OutputResultExtension for OutputResult {
    /// Map the protobuf OutputResult type to a more idiomatic rust Result type
    fn status(&self) -> Result<Option<(TxOut, TxOutMembershipProof)>, OutputError> {
        // Rust does not allow the left side of match expression to a be `Foo as u32`.
        const OUTPUT_RESULT_CODE_EXISTS: u32 = mc_fog_api::ledger::OutputResultCode::Exists as u32;
        const OUTPUT_RESULT_CODE_DOES_NOT_EXIST: u32 =
            mc_fog_api::ledger::OutputResultCode::DoesNotExist as u32;
        const OUTPUT_RESULT_CODE_DATABASE_ERROR: u32 =
            mc_fog_api::ledger::OutputResultCode::OutputDatabaseError as u32;

        match self.result_code {
            OUTPUT_RESULT_CODE_EXISTS => Ok(Some((self.output.clone(), self.proof.clone()))),
            OUTPUT_RESULT_CODE_DOES_NOT_EXIST => Ok(None),
            OUTPUT_RESULT_CODE_DATABASE_ERROR => Err(OutputError::DatabaseError),
            other => Err(OutputError::UnknownError(other)),
        }
    }
}

/// Errors that occur in regards to an individual GetOutput query.
#[derive(Clone, Display, Debug, Eq, PartialEq)]
pub enum OutputError {
    /// The server reported a database error
    DatabaseError,
    /// The server returned an unknown output status code
    UnknownError(u32),
}
