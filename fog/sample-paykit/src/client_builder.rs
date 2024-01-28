// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Client Builder

use crate::client::Client;
use grpcio::EnvBuilder;
use mc_account_keys::{AccountKey, PublicAddress};
use mc_attestation_verifier::{TrustedIdentity, TrustedMrSignerIdentity};
use mc_common::logger::{log, o, Logger};
use mc_connection::{HardcodedCredentialsProvider, ThickClient};
use mc_fog_ledger_connection::{
    FogBlockGrpcClient, FogKeyImageGrpcClient, FogMerkleProofGrpcClient,
    FogUntrustedLedgerGrpcClient,
};
use mc_fog_report_connection::GrpcFogReportConnection;
use mc_fog_uri::{FogLedgerUri, FogViewUri};
use mc_fog_view_connection::FogViewGrpcClient;
use mc_sgx_css::Signature;
use mc_transaction_core::constants::RING_SIZE;
use mc_util_grpc::GrpcRetryConfig;
use mc_util_uri::{ConnectionUri, ConsensusClientUri};
use std::sync::Arc;

/// Builder object which helps to initialize the sample paykit
pub struct ClientBuilder {
    // Required
    chain_id: String,
    uri: ConsensusClientUri,
    key: AccountKey,
    logger: Logger,

    // Optional, has sane defaults
    grpc_retry_config: GrpcRetryConfig,

    // Optional, has sane defaults
    ring_size: usize,

    // Uris to fog services
    fog_view_address: FogViewUri,
    ledger_server_address: FogLedgerUri,

    // Address book, for memos
    address_book: Vec<PublicAddress>,

    // Optional sigstructs for attested services
    consensus_sigstruct: Option<Signature>,
    fog_ingest_sigstruct: Option<Signature>,
    fog_ledger_sigstruct: Option<Signature>,
    fog_view_sigstruct: Option<Signature>,
}

impl ClientBuilder {
    /// Create a new client builder object
    pub fn new(
        chain_id: String,
        uri: ConsensusClientUri,
        fog_view_address: FogViewUri,
        ledger_server_address: FogLedgerUri,
        key: AccountKey,
        logger: Logger,
    ) -> Self {
        Self {
            chain_id,
            uri,
            key,
            logger,
            grpc_retry_config: Default::default(),
            ring_size: RING_SIZE,
            fog_view_address,
            ledger_server_address,
            address_book: Default::default(),
            consensus_sigstruct: None,
            fog_ingest_sigstruct: None,
            fog_ledger_sigstruct: None,
            fog_view_sigstruct: None,
        }
    }

    /// Sets the grpc retry configuration
    #[must_use]
    pub fn grpc_retry_config(mut self, config: GrpcRetryConfig) -> Self {
        self.grpc_retry_config = config;
        self
    }

    /// Sets the ring size to be used when generating transactions.
    #[must_use]
    pub fn ring_size(mut self, ring_size: usize) -> Self {
        self.ring_size = ring_size;
        self
    }

    /// Sets the address book for the client, used with memos
    #[must_use]
    pub fn address_book(mut self, address_book: Vec<PublicAddress>) -> Self {
        self.address_book = address_book;
        self
    }

    /// Sets the consensus sigstruct
    #[must_use]
    pub fn consensus_sig(mut self, sig: Option<Signature>) -> Self {
        self.consensus_sigstruct = sig;
        self
    }

    /// Sets the fog ingest sigstruct
    #[must_use]
    pub fn fog_ingest_sig(mut self, sig: Option<Signature>) -> Self {
        self.fog_ingest_sigstruct = sig;
        self
    }

    /// Sets the fog ledger sigstruct
    #[must_use]
    pub fn fog_ledger_sig(mut self, sig: Option<Signature>) -> Self {
        self.fog_ledger_sigstruct = sig;
        self
    }

    /// Sets the fog view sigstruct
    #[must_use]
    pub fn fog_view_sig(mut self, sig: Option<Signature>) -> Self {
        self.fog_view_sigstruct = sig;
        self
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
            "About to start LedgerServerConn to {}",
            self.ledger_server_address
        );
        let (fog_merkle_proof, fog_key_image, fog_untrusted, fog_block) =
            self.build_fog_ledger_server_conns(grpc_env.clone());

        let identity = self.consensus_identity();

        log::debug!(
            self.logger,
            "Consensus attestation identity: {:?}",
            identity
        );

        let consensus_service_conn = ThickClient::new(
            self.chain_id.clone(),
            self.uri.clone(),
            [identity],
            grpc_env.clone(),
            HardcodedCredentialsProvider::from(&self.uri),
            self.logger.new(o!("mc.cxn" => self.uri.addr())),
        )
        .expect("ThickClient::new returned an error");

        let fog_ingest_identity = self.fog_ingest_identity();

        log::debug!(
            self.logger,
            "Fog ingest attestation identity: {:?}",
            fog_ingest_identity
        );

        let fog_report_conn =
            GrpcFogReportConnection::new(self.chain_id.clone(), grpc_env, self.logger.clone());

        Client::new(
            consensus_service_conn,
            fog_view_client,
            fog_merkle_proof,
            fog_key_image,
            fog_block,
            fog_report_conn,
            [fog_ingest_identity],
            fog_untrusted,
            self.ring_size,
            self.key,
            self.address_book,
            self.logger,
        )
    }

    // Build a Fog View connection, taking into account acct_host_override
    // and default port
    fn build_fog_view_conn(&self, grpc_env: Arc<grpcio::Environment>) -> FogViewGrpcClient {
        let identity = self.fog_view_identity();

        log::debug!(self.logger, "Fog view attestation identity: {:?}", identity);

        FogViewGrpcClient::new(
            self.chain_id.clone(),
            self.fog_view_address.clone(),
            self.grpc_retry_config,
            [identity],
            grpc_env,
            self.logger.clone(),
        )
    }

    // Build a Fog Ledger connection.
    fn build_fog_ledger_server_conns(
        &self,
        grpc_env: Arc<grpcio::Environment>,
    ) -> (
        FogMerkleProofGrpcClient,
        FogKeyImageGrpcClient,
        FogUntrustedLedgerGrpcClient,
        FogBlockGrpcClient,
    ) {
        let identity = self.fog_ledger_identity();

        log::debug!(
            self.logger,
            "Fog ledger attestation identity: {:?}",
            identity
        );

        (
            FogMerkleProofGrpcClient::new(
                self.chain_id.clone(),
                self.ledger_server_address.clone(),
                self.grpc_retry_config,
                [identity.clone()],
                grpc_env.clone(),
                self.logger.clone(),
            ),
            FogKeyImageGrpcClient::new(
                self.chain_id.clone(),
                self.ledger_server_address.clone(),
                self.grpc_retry_config,
                [identity],
                grpc_env.clone(),
                self.logger.clone(),
            ),
            FogUntrustedLedgerGrpcClient::new(
                self.ledger_server_address.clone(),
                self.grpc_retry_config,
                grpc_env.clone(),
                self.logger.clone(),
            ),
            FogBlockGrpcClient::new(
                self.ledger_server_address.clone(),
                self.grpc_retry_config,
                grpc_env,
                self.logger.clone(),
            ),
        )
    }

    // Get consensus attestation identity (dynamic or build time, MRSIGNER)
    fn consensus_identity(&self) -> TrustedIdentity {
        if let Some(signature) = self.consensus_sigstruct.as_ref() {
            let mr_signer_identity = TrustedMrSignerIdentity::new(
                signature.mrsigner().into(),
                signature.product_id(),
                signature.version(),
                [] as [&str; 0],
                mc_consensus_enclave_measurement::HARDENING_ADVISORIES,
            );
            mr_signer_identity.into()
        } else {
            mc_consensus_enclave_measurement::mr_signer_identity(None)
        }
    }

    // Get fog ingest attestation identity (dynamic or build time, MRSIGNER)
    fn fog_ingest_identity(&self) -> TrustedIdentity {
        if let Some(signature) = self.fog_ingest_sigstruct.as_ref() {
            let mr_signer_identity = TrustedMrSignerIdentity::new(
                signature.mrsigner().into(),
                signature.product_id(),
                signature.version(),
                [] as [&str; 0],
                mc_fog_ingest_enclave_measurement::HARDENING_ADVISORIES,
            );
            mr_signer_identity.into()
        } else {
            mc_fog_ingest_enclave_measurement::mr_signer_identity(None)
        }
    }

    // Get fog ledger attestation identity (dynamic or build time, MRSIGNER)
    fn fog_ledger_identity(&self) -> TrustedIdentity {
        if let Some(signature) = self.fog_ledger_sigstruct.as_ref() {
            let mr_signer_identity = TrustedMrSignerIdentity::new(
                signature.mrsigner().into(),
                signature.product_id(),
                signature.version(),
                [] as [&str; 0],
                mc_fog_ledger_enclave_measurement::HARDENING_ADVISORIES,
            );
            mr_signer_identity.into()
        } else {
            mc_fog_ledger_enclave_measurement::mr_signer_identity(None)
        }
    }

    // Get fog view attestation identity (dynamic or build time, MRSIGNER)
    fn fog_view_identity(&self) -> TrustedIdentity {
        if let Some(signature) = self.fog_view_sigstruct.as_ref() {
            let mr_signer_identity = TrustedMrSignerIdentity::new(
                signature.mrsigner().into(),
                signature.product_id(),
                signature.version(),
                [] as [&str; 0],
                mc_fog_view_enclave_measurement::HARDENING_ADVISORIES,
            );
            mr_signer_identity.into()
        } else {
            mc_fog_view_enclave_measurement::mr_signer_identity(None)
        }
    }
}
