// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Client Builder

use crate::client::Client;
use grpcio::EnvBuilder;
use mc_account_keys::{AccountKey, PublicAddress};
use mc_attest_verifier::{MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
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
use mc_util_uri::{ConnectionUri, ConsensusClientUri};
use std::sync::Arc;

/// Builder object which helps to initialize the sample paykit
pub struct ClientBuilder {
    // Required
    uri: ConsensusClientUri,
    key: AccountKey,
    logger: Logger,

    // Optional, has sane defaults
    ring_size: usize,

    // Whether to use memos. For backwards compat, turn this off
    use_rth_memos: bool,

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
        uri: ConsensusClientUri,
        fog_view_address: FogViewUri,
        ledger_server_address: FogLedgerUri,
        key: AccountKey,
        logger: Logger,
    ) -> Self {
        Self {
            uri,
            key,
            logger,
            ring_size: RING_SIZE,
            use_rth_memos: true,
            fog_view_address,
            ledger_server_address,
            address_book: Default::default(),
            consensus_sigstruct: None,
            fog_ingest_sigstruct: None,
            fog_ledger_sigstruct: None,
            fog_view_sigstruct: None,
        }
    }

    /// Sets the ring size to be used when generating transactions.
    pub fn ring_size(self, ring_size: usize) -> Self {
        let mut retval = self;
        retval.ring_size = ring_size;
        retval
    }

    /// Sets whether or not to use memos
    pub fn use_rth_memos(self, flag: bool) -> Self {
        let mut retval = self;
        retval.use_rth_memos = flag;
        retval
    }

    /// Sets the address book for the client, used with memos
    pub fn address_book(self, address_book: Vec<PublicAddress>) -> Self {
        let mut retval = self;
        retval.address_book = address_book;
        retval
    }

    /// Sets the consensus sigstruct
    pub fn consensus_sig(self, sig: Option<Signature>) -> Self {
        let mut retval = self;
        retval.consensus_sigstruct = sig;
        retval
    }

    /// Sets the fog ingest sigstruct
    pub fn fog_ingest_sig(self, sig: Option<Signature>) -> Self {
        let mut retval = self;
        retval.fog_ingest_sigstruct = sig;
        retval
    }

    /// Sets the fog ledger sigstruct
    pub fn fog_ledger_sig(self, sig: Option<Signature>) -> Self {
        let mut retval = self;
        retval.fog_ledger_sigstruct = sig;
        retval
    }

    /// Sets the fog view sigstruct
    pub fn fog_view_sig(self, sig: Option<Signature>) -> Self {
        let mut retval = self;
        retval.fog_view_sigstruct = sig;
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
        let (fog_merkle_proof, fog_key_image, fog_untrusted, fog_block) =
            self.build_fog_ledger_server_conns(grpc_env.clone());

        let verifier = self.get_consensus_verifier();

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

        let fog_ingest_verifier = self.get_fog_ingest_verifier();

        log::debug!(
            self.logger,
            "Fog ingest attestation verifier: {:?}",
            fog_ingest_verifier
        );

        let fog_report_conn = GrpcFogReportConnection::new(grpc_env, self.logger.clone());

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
            self.key.clone(),
            self.address_book.clone(),
            self.use_rth_memos,
            self.logger.clone(),
        )
    }

    // Build a Fog View connection, taking into account acct_host_override
    // and default port
    fn build_fog_view_conn(&self, grpc_env: Arc<grpcio::Environment>) -> FogViewGrpcClient {
        let verifier = self.get_fog_view_verifier();

        log::debug!(self.logger, "Fog view attestation verifier: {:?}", verifier);

        FogViewGrpcClient::new(
            self.fog_view_address.clone(),
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

        log::debug!(
            self.logger,
            "Fog ledger attestation verifier: {:?}",
            verifier
        );

        (
            FogMerkleProofGrpcClient::new(
                self.ledger_server_address.clone(),
                verifier.clone(),
                grpc_env.clone(),
                self.logger.clone(),
            ),
            FogKeyImageGrpcClient::new(
                self.ledger_server_address.clone(),
                verifier,
                grpc_env.clone(),
                self.logger.clone(),
            ),
            FogUntrustedLedgerGrpcClient::new(
                self.ledger_server_address.clone(),
                grpc_env.clone(),
                self.logger.clone(),
            ),
            FogBlockGrpcClient::new(
                self.ledger_server_address.clone(),
                grpc_env,
                self.logger.clone(),
            ),
        )
    }

    // Get consensus verifier (dynamic or build time, MRSIGNER)
    fn get_consensus_verifier(&self) -> Verifier {
        let mr_signer_verifier = if let Some(signature) = self.consensus_sigstruct.as_ref() {
            let mut mr_signer_verifier = MrSignerVerifier::new(
                signature.mrsigner().into(),
                signature.product_id(),
                signature.version(),
            );
            mr_signer_verifier.allow_hardening_advisories(&["INTEL-SA-00334"]);
            mr_signer_verifier
        } else {
            mc_consensus_enclave_measurement::get_mr_signer_verifier(None)
        };

        let mut verifier = Verifier::default();
        verifier.debug(DEBUG_ENCLAVE).mr_signer(mr_signer_verifier);
        verifier
    }

    // Get fog ingest verifier (dynamic or build time, MRSIGNER)
    fn get_fog_ingest_verifier(&self) -> Verifier {
        let mr_signer_verifier = if let Some(signature) = self.fog_ingest_sigstruct.as_ref() {
            let mut mr_signer_verifier = MrSignerVerifier::new(
                signature.mrsigner().into(),
                signature.product_id(),
                signature.version(),
            );
            mr_signer_verifier.allow_hardening_advisories(&["INTEL-SA-00334"]);
            mr_signer_verifier
        } else {
            mc_fog_ingest_enclave_measurement::get_mr_signer_verifier(None)
        };

        let mut verifier = Verifier::default();
        verifier.debug(DEBUG_ENCLAVE).mr_signer(mr_signer_verifier);
        verifier
    }

    // Get fog ledger verifier (dynamic or build time, MRSIGNER)
    fn get_fog_ledger_verifier(&self) -> Verifier {
        let mr_signer_verifier = if let Some(signature) = self.fog_ledger_sigstruct.as_ref() {
            let mut mr_signer_verifier = MrSignerVerifier::new(
                signature.mrsigner().into(),
                signature.product_id(),
                signature.version(),
            );
            mr_signer_verifier.allow_hardening_advisories(&["INTEL-SA-00334"]);
            mr_signer_verifier
        } else {
            mc_fog_ledger_enclave_measurement::get_mr_signer_verifier(None)
        };

        let mut verifier = Verifier::default();
        verifier.debug(DEBUG_ENCLAVE).mr_signer(mr_signer_verifier);
        verifier
    }

    // Get fog view verifier (dynamic or build time, MRSIGNER)
    fn get_fog_view_verifier(&self) -> Verifier {
        let mr_signer_verifier = if let Some(signature) = self.fog_view_sigstruct.as_ref() {
            let mut mr_signer_verifier = MrSignerVerifier::new(
                signature.mrsigner().into(),
                signature.product_id(),
                signature.version(),
            );
            mr_signer_verifier.allow_hardening_advisories(&["INTEL-SA-00334"]);
            mr_signer_verifier
        } else {
            mc_fog_view_enclave_measurement::get_mr_signer_verifier(None)
        };

        let mut verifier = Verifier::default();
        verifier.debug(DEBUG_ENCLAVE).mr_signer(mr_signer_verifier);
        verifier
    }
}
