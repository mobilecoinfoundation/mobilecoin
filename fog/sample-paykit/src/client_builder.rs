// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Client Builder

use crate::client::Client;
use grpcio::EnvBuilder;
use mc_account_keys::{AccountKey, PublicAddress};
use mc_attest_verifier::{MrEnclaveVerifier, Verifier, DEBUG_ENCLAVE};
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

    // Optional additional sigstructs for attested services
    consensus_sigstruct: Vec<Signature>,
    fog_ingest_sigstruct: Vec<Signature>,
    fog_ledger_sigstruct: Vec<Signature>,
    fog_view_sigstruct: Vec<Signature>,
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
            consensus_sigstruct: Default::default(),
            fog_ingest_sigstruct: Default::default(),
            fog_ledger_sigstruct: Default::default(),
            fog_view_sigstruct: Default::default(),
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

    /// Pushes multiple consensus sigstructs, to additionally be trusted
    #[must_use]
    pub fn consensus_sigs(mut self, sigs: Vec<Signature>) -> Self {
        self.consensus_sigstruct.extend(sigs);
        self
    }

    /// Pushes multiple fog ingest sigstructs, to additionally be trusted
    #[must_use]
    pub fn fog_ingest_sigs(mut self, sigs: Vec<Signature>) -> Self {
        self.fog_ingest_sigstruct.extend(sigs);
        self
    }

    /// Pushes multiple fog ledger sigstructs, to additionally be trusted
    #[must_use]
    pub fn fog_ledger_sigs(mut self, sigs: Vec<Signature>) -> Self {
        self.fog_ledger_sigstruct.extend(sigs);
        self
    }

    /// Pushes multiple fog view sigstructs, to additionally be trusted
    #[must_use]
    pub fn fog_view_sigs(mut self, sigs: Vec<Signature>) -> Self {
        self.fog_view_sigstruct.extend(sigs);
        self
    }

    /// Create the client
    #[must_use]
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

        let consensus_verifier = self.get_consensus_verifier();
        let consensus_service_conn = ThickClient::new(
            self.chain_id.clone(),
            self.uri.clone(),
            consensus_verifier,
            grpc_env.clone(),
            HardcodedCredentialsProvider::from(&self.uri),
            self.logger.new(o!("mc.cxn" => self.uri.addr())),
        )
        .expect("ThickClient::new returned an error");

        let fog_ingest_verifier = self.get_fog_ingest_verifier();
        let fog_report_conn =
            GrpcFogReportConnection::new(self.chain_id.clone(), grpc_env, self.logger.clone());

        Client::new(
            consensus_service_conn,
            fog_view_client,
            fog_merkle_proof,
            fog_key_image,
            fog_block,
            fog_report_conn,
            fog_ingest_verifier,
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
        let verifier = self.get_fog_view_verifier();

        FogViewGrpcClient::new(
            self.chain_id.clone(),
            self.fog_view_address.clone(),
            self.grpc_retry_config,
            verifier,
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
        let verifier = self.get_fog_ledger_verifier();

        (
            FogMerkleProofGrpcClient::new(
                self.chain_id.clone(),
                self.ledger_server_address.clone(),
                self.grpc_retry_config,
                verifier.clone(),
                grpc_env.clone(),
                self.logger.clone(),
            ),
            FogKeyImageGrpcClient::new(
                self.chain_id.clone(),
                self.ledger_server_address.clone(),
                self.grpc_retry_config,
                verifier,
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

    // Get consensus verifier (dynamic + build time, MRENCLAVE)
    fn get_consensus_verifier(&self) -> Verifier {
        let mut verifier = Verifier::default();
        verifier.debug(DEBUG_ENCLAVE);

        let mut mr_enclave_verifier =
            MrEnclaveVerifier::from(mc_consensus_enclave_measurement::sigstruct());
        mr_enclave_verifier
            .allow_hardening_advisories(mc_consensus_enclave_measurement::HARDENING_ADVISORIES);
        verifier.mr_enclave(mr_enclave_verifier);

        for sig in &self.consensus_sigstruct {
            let mut mr_enclave_verifier = MrEnclaveVerifier::from(sig.clone());
            mr_enclave_verifier
                .allow_hardening_advisories(mc_consensus_enclave_measurement::HARDENING_ADVISORIES);
            verifier.mr_enclave(mr_enclave_verifier);
        }

        log::debug!(self.logger, "Consensus Verifier: {:?}", verifier);

        verifier
    }

    // Get fog ingest verifier (dynamic + build time, MRENCLAVE)
    fn get_fog_ingest_verifier(&self) -> Verifier {
        let mut verifier = Verifier::default();
        verifier.debug(DEBUG_ENCLAVE);

        let mut mr_enclave_verifier =
            MrEnclaveVerifier::from(mc_fog_ingest_enclave_measurement::sigstruct());
        mr_enclave_verifier
            .allow_hardening_advisories(mc_fog_ingest_enclave_measurement::HARDENING_ADVISORIES);
        verifier.mr_enclave(mr_enclave_verifier);

        for sig in &self.fog_ingest_sigstruct {
            let mut mr_enclave_verifier = MrEnclaveVerifier::from(sig.clone());
            mr_enclave_verifier.allow_hardening_advisories(
                mc_fog_ingest_enclave_measurement::HARDENING_ADVISORIES,
            );
            verifier.mr_enclave(mr_enclave_verifier);
        }

        log::debug!(self.logger, "Fog Ingest Verifier: {:?}", verifier);

        verifier
    }

    // Get fog ledger verifier (dynamic + build time, MRENCLAVE)
    fn get_fog_ledger_verifier(&self) -> Verifier {
        let mut verifier = Verifier::default();
        verifier.debug(DEBUG_ENCLAVE);

        let mut mr_enclave_verifier =
            MrEnclaveVerifier::from(mc_fog_ledger_enclave_measurement::sigstruct());
        mr_enclave_verifier
            .allow_hardening_advisories(mc_fog_ledger_enclave_measurement::HARDENING_ADVISORIES);
        verifier.mr_enclave(mr_enclave_verifier);

        for sig in &self.fog_ledger_sigstruct {
            let mut mr_enclave_verifier = MrEnclaveVerifier::from(sig.clone());
            mr_enclave_verifier.allow_hardening_advisories(
                mc_fog_ledger_enclave_measurement::HARDENING_ADVISORIES,
            );
            verifier.mr_enclave(mr_enclave_verifier);
        }

        log::debug!(self.logger, "Fog Ledger Verifier: {:?}", verifier);

        verifier
    }

    // Get fog view verifier (dynamic + build time, MRENCLAVE)
    fn get_fog_view_verifier(&self) -> Verifier {
        let mut verifier = Verifier::default();
        verifier.debug(DEBUG_ENCLAVE);

        let mut mr_enclave_verifier =
            MrEnclaveVerifier::from(mc_fog_view_enclave_measurement::sigstruct());
        mr_enclave_verifier
            .allow_hardening_advisories(mc_fog_view_enclave_measurement::HARDENING_ADVISORIES);
        verifier.mr_enclave(mr_enclave_verifier);

        for sig in &self.fog_view_sigstruct {
            let mut mr_enclave_verifier = MrEnclaveVerifier::from(sig.clone());
            mr_enclave_verifier
                .allow_hardening_advisories(mc_fog_view_enclave_measurement::HARDENING_ADVISORIES);
            verifier.mr_enclave(mr_enclave_verifier);
        }

        log::debug!(self.logger, "Fog View Verifier: {:?}", verifier);

        verifier
    }
}
