// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The message types used by the ingest_enclave_api.

use mc_attest_core::{Quote, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{EnclaveMessage, PeerAuthRequest, PeerAuthResponse, PeerSession};
use mc_fog_types::ingest::TxsForIngest;
use serde::{Deserialize, Serialize};

use crate::{ResponderId, SealedIngestKey};

/// Parameters to the ingest enclave init() call
/// TODO: Make this prost compatible
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IngestEnclaveInitParams {
    /// The ResponderId to use with AKE, when peering to other ingest enclaves
    pub responder_id: ResponderId,
    /// The sealed fog private key to reload this ingest enclave with
    pub sealed_key: Option<SealedIngestKey>,
    /// The desired capcacity for users of the oblivious map. Must be a power of
    /// two. This will be the capacity if the hashtable achieved a 100%
    /// load-factor, a more realistic maximum capacity is 70-75%.
    pub desired_capacity: u64,
}

/// An enumeration of API calls and their arguments for use across serialization
/// boundaries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EnclaveCall {
    /// The [IngestEnclave::enclave_init()] method.
    EnclaveInit(IngestEnclaveInitParams),

    /// The [IngestEnclave::new_keys()] method.
    NewKeys,

    /// The [IngestEnclave::new_egress_key()] method.
    NewEgressKey,

    /// The [IngestEnclave::get_ingress_pubkey()] method.
    ///
    /// Retrieves the ingress public key (RistrettoPublic) of this service.
    GetIngressPubkey,

    /// The [IngestEnclave::get_sealed_ingress_private_key()] method
    GetSealedIngressPrivateKey,

    /// The [IngestEnclave::get_private_key()] method.
    ///
    /// Retrieves the peer-encrypted ingress private key (as attest::Message) of
    /// this service.
    GetIngressPrivateKey(PeerSession),

    /// The [IngestEnclave::set_private_key()] method.
    ///
    /// Sets the ingress private key (passed as attest::Message from attested
    /// peer) of this service.
    SetIngressPrivateKey(EnclaveMessage<PeerSession>),

    /// The [IngestEnclave::get_kex_rng_pubkey()] method.
    ///
    /// Retrieves the KexRngPubkey object, containing public key of egress key
    /// and the rng algo version.
    GetKexRngPubkey,

    /// The [IngestEnclave::ingest_txs()] method.
    ///
    /// Consumes transactions and emits corresponding rows for the recovery
    /// database.
    IngestTxs(TxsForIngest),

    /// The [IngestEnclave::get_identity()] method.
    ///
    /// Retrieves the public identity (X25519 public key) of an enclave.
    GetIdentity,

    /// The [IngestEnclave::new_ereport()] method.
    ///
    /// Creates a new report for the enclave with the provided target info.
    NewEreport(TargetInfo),

    /// The [IngestEnclave::verify_quote()] method.
    ///
    /// * Verifies that the Quoting Enclave is sane,
    /// * Verifies that the Quote matches the previously generated report.
    /// * Caches the quote.
    VerifyQuote(Quote, Report),

    /// The [IngestEnclave::verify_ias_report()] method.
    ///
    /// * Verifies the signed report from IAS matches the previously received
    ///   quote,
    /// * Caches the signed report. This cached report may be overwritten by
    ///   later calls.
    VerifyReport(VerificationReport),

    /// The [IngestEnclave::get_ias_report()] method.
    ///
    /// Retrieves a previously cached report, if any.
    GetReport,

    /// The [IngestEnclave::peer_init()] method.
    PeerInit(ResponderId),
    /// The [IngestEnclave::peer_accept()] method.
    PeerAccept(PeerAuthRequest),
    /// The [IngestEnclave::peer_connect()] method.
    PeerConnect(ResponderId, PeerAuthResponse),
    /// The [IngestEnclave::peer_close()] method.
    PeerClose(PeerSession),
}
