// Copyright (c) 2018-2021 The MobileCoin Foundation

use super::Error;
use displaydoc::Display;
use fog_api::{ledger::KeyImageResultCode, ledger_grpc};
use fog_enclave_connection::EnclaveConnection;
use fog_uri::FogLedgerUri;
use grpcio::{ChannelBuilder, Environment};
use mc_attest_core::Verifier;
use mc_common::logger::{o, Logger};
use mc_transaction_core::{ring_signature::KeyImage, BlockIndex};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use std::sync::Arc;

/// An attested connection to the Fog Key Image service.
pub struct FogKeyImageGrpcClient {
    conn: EnclaveConnection<FogLedgerUri, ledger_grpc::FogKeyImageApiClient>,
}

impl FogKeyImageGrpcClient {
    /// Create a new client object
    pub fn new(
        uri: FogLedgerUri,
        verifier: Verifier,
        env: Arc<Environment>,
        logger: Logger,
    ) -> Self {
        let logger = logger.new(o!("mc.ledger.cxn" => uri.to_string()));

        let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&uri, &logger);

        let grpc_client = ledger_grpc::FogKeyImageApiClient::new(ch);

        Self {
            conn: EnclaveConnection::new(uri, grpc_client, verifier, logger),
        }
    }

    /// Make a private request to check the validity of several key images
    pub fn check_key_images(
        &mut self,
        key_images: &[KeyImage],
    ) -> Result<fog_types::ledger::CheckKeyImagesResponse, Error> {
        let request = fog_types::ledger::CheckKeyImagesRequest {
            queries: key_images
                .iter()
                .map(|key_image| fog_types::ledger::KeyImageQuery {
                    key_image: *key_image,
                    start_block: 0,
                })
                .collect(),
        };

        let response: fog_types::ledger::CheckKeyImagesResponse =
            self.conn.encrypted_enclave_request(&request, &[])?;

        Ok(response)
    }
}

/// An extension trait that adds a convenience method to check the status of a
/// key image result.
pub trait KeyImageResultExtension {
    /// Check the status of a key image query. A `None` value indicates the key
    /// image has not been found. Some(spent_at) indicates the key image
    /// appeared at block index `spent_at`.
    fn status(&self) -> Result<Option<BlockIndex>, KeyImageQueryError>;
}

impl KeyImageResultExtension for fog_types::ledger::KeyImageResult {
    /// Map the protobuf KeyImageResult type to a more idiomatic rust Result
    /// type
    fn status(&self) -> Result<Option<BlockIndex>, KeyImageQueryError> {
        if self.key_image_result_code == KeyImageResultCode::Spent as u32 {
            Ok(Some(self.spent_at))
        } else if self.key_image_result_code == KeyImageResultCode::NotSpent as u32 {
            Ok(None)
        } else if self.key_image_result_code == KeyImageResultCode::KeyImageError as u32 {
            Err(KeyImageQueryError::KeyImageError)
        } else {
            Err(KeyImageQueryError::UnknownStatus(
                self.key_image_result_code,
            ))
        }
    }
}

/// Errors that occur from an individual check key image query
#[derive(Display, Debug, Eq, PartialEq)]
pub enum KeyImageQueryError {
    /// Nonspecific server error handling the request
    // FIXME: The server should at least seperate "invalid key image", "rate
    // limited", "database", from other error types
    KeyImageError,
    /// Unknown status code: {0}
    UnknownStatus(u32),
}
