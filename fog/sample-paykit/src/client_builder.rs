// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Client Builder

use crate::client::Client;
use grpcio::EnvBuilder;
use mc_account_keys::{AccountKey, PublicAddress};
use mc_attest_core::{Verifier, DEBUG_ENCLAVE};
use mc_common::logger::{log, o, Logger};
use mc_connection::{HardcodedCredentialsProvider, ThickClient};
use mc_fog_ledger_connection::{
    FogKeyImageGrpcClient, FogMerkleProofGrpcClient, FogUntrustedLedgerGrpcClient,
};
use mc_fog_report_connection::GrpcFogReportConnection;
use mc_fog_uri::{FogLedgerUri, FogViewUri};
use mc_fog_view_connection::FogViewGrpcClient;
use mc_transaction_core::constants::RING_SIZE;
use mc_util_uri::{ConnectionUri, ConsensusClientUri};
use std::{str::FromStr, sync::Arc};

/// Builder object which helps to initialize the sample paykit
/// TODO: FOG-219 This is very messy right now, due to a lot of old tech debt.
/// It's possible that the entire builder object should go away, since the scope
/// of sample paykit has been reduced so much.
pub struct ClientBuilder {
    // Required
    uri: ConsensusClientUri,
    key: AccountKey,
    logger: Logger,

    // Optional, has sane defaults
    ring_size: usize,

    fog_view: String,

    // Ledger Server Details
    ledger_server_address: String,

    // Address book
    address_book: Vec<PublicAddress>,
}

// FIXME: ledger_server_address should be split into key_image_server and
// merkle_proof_server
impl ClientBuilder {
    /// Create a new client builder object
    pub fn new(
        uri: ConsensusClientUri,
        fog_view_address: String,
        ledger_server_address: String,
        key: AccountKey,
        logger: Logger,
    ) -> Self {
        Self {
            uri,
            key,
            logger,
            ring_size: RING_SIZE,
            fog_view: fog_view_address,
            ledger_server_address,
            address_book: Default::default(),
        }
    }

    /// Sets the ring size to be used when generating transactions.
    pub fn ring_size(self, ring_size: usize) -> Self {
        let mut retval = self;
        retval.ring_size = ring_size;
        retval
    }

    /// Sets the address book for the client, used with memos
    pub fn address_book(self, address_book: Vec<PublicAddress>) -> Self {
        let mut retval = self;
        retval.address_book = address_book;
        retval
    }

    /// Create the client
    pub fn build(self) -> Client {
        let grpc_env = Arc::new(
            EnvBuilder::new()
                .name_prefix(format!("sdk-{}", self.uri.addr()))
                .build(),
        );

        let fog_view_client = self.build_fog_view_conn(grpc_env.clone());

        log::info!(
            self.logger,
            "About to start LedgerServerConn to {:?}",
            self.ledger_server_address.clone()
        );
        let (fog_merkle_proof, fog_key_image, fog_untrusted) =
            self.build_fog_ledger_server_conns(grpc_env.clone());

        let verifier = {
            let mr_signer_verifier = mc_consensus_enclave_measurement::get_mr_signer_verifier(None);

            let mut verifier = Verifier::default();
            verifier.mr_signer(mr_signer_verifier).debug(DEBUG_ENCLAVE);
            verifier
        };

        log::debug!(
            self.logger,
            "Consensus attestation verifier: {:?}",
            verifier
        );

        let consensus_service_conn = ThickClient::new(
            self.uri.clone(),
            verifier,
            grpc_env.clone(),
            HardcodedCredentialsProvider::from(&self.uri),
            self.logger.new(o!("mc.cxn" => self.uri.addr())),
        )
        .expect("ThickClient::new returned an error");

        let fog_verifier = {
            let mr_signer_verifier =
                mc_fog_ingest_enclave_measurement::get_mr_signer_verifier(None);

            let mut verifier = Verifier::default();
            verifier.debug(DEBUG_ENCLAVE).mr_signer(mr_signer_verifier);
            verifier
        };

        log::debug!(
            self.logger,
            "Fog ingest attestation verifier: {:?}",
            fog_verifier
        );

        let fog_report_conn = GrpcFogReportConnection::new(grpc_env, self.logger.clone());

        Client::new(
            consensus_service_conn,
            fog_view_client,
            fog_merkle_proof,
            fog_key_image,
            fog_report_conn,
            fog_verifier,
            fog_untrusted,
            self.ring_size,
            self.key.clone(),
            self.address_book.clone(),
            self.logger.clone(),
        )
    }

    // Build a Fog View connection, taking into account acct_host_override
    // and default port
    fn build_fog_view_conn(&self, grpc_env: Arc<grpcio::Environment>) -> FogViewGrpcClient {
        let verifier = {
            let mr_signer_verifier = mc_fog_view_enclave_measurement::get_mr_signer_verifier(None);

            let mut verifier = Verifier::default();
            verifier.mr_signer(mr_signer_verifier).debug(DEBUG_ENCLAVE);
            verifier
        };

        log::debug!(self.logger, "Fog view attestation verifier: {:?}", verifier);

        let client_uri = FogViewUri::from_str(&self.fog_view)
            .unwrap_or_else(|e| panic!("Could not parse client uri: {}: {:?}", self.fog_view, e));

        FogViewGrpcClient::new(client_uri, verifier, grpc_env, self.logger.clone())
    }

    // Build a Fog Ledger connection.
    fn build_fog_ledger_server_conns(
        &self,
        grpc_env: Arc<grpcio::Environment>,
    ) -> (
        FogMerkleProofGrpcClient,
        FogKeyImageGrpcClient,
        FogUntrustedLedgerGrpcClient,
    ) {
        let verifier = {
            let mr_signer_verifier =
                mc_fog_ledger_enclave_measurement::get_mr_signer_verifier(None);

            let mut verifier = Verifier::default();
            verifier.mr_signer(mr_signer_verifier).debug(DEBUG_ENCLAVE);
            verifier
        };

        log::debug!(
            self.logger,
            "Fog ledger attestation verifier: {:?}",
            verifier
        );

        let client_uri = FogLedgerUri::from_str(&self.ledger_server_address).unwrap_or_else(|e| {
            panic!(
                "Could not parse client uri: {}: {:?}",
                self.ledger_server_address, e
            )
        });

        (
            FogMerkleProofGrpcClient::new(
                client_uri.clone(),
                verifier.clone(),
                grpc_env.clone(),
                self.logger.clone(),
            ),
            FogKeyImageGrpcClient::new(
                client_uri.clone(),
                verifier,
                grpc_env.clone(),
                self.logger.clone(),
            ),
            FogUntrustedLedgerGrpcClient::new(client_uri, grpc_env, self.logger.clone()),
        )
    }
}
