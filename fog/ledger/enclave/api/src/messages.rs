// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The message types used by the ledger_enclave_api.
use crate::UntrustedKeyImageQueryResponse;
use alloc::vec::Vec;
use mc_attest_core::{Quote, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{ClientAuthRequest, ClientSession, EnclaveMessage};
use mc_common::ResponderId;
use mc_fog_types::ledger::GetOutputsResponse;
use mc_transaction_core::ring_signature::KeyImage;
use serde::{Deserialize, Serialize};

/// A struct representing the key image stores data
#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    PartialOrd,
    core::cmp::Eq,
    core::hash::Hash,
    Ord,
)]
pub struct KeyImageData {
    /// A key image which has appeared in the blockchain
    pub key_image: KeyImage,
    /// The index of the block in which this key image appeared
    pub block_index: u64,
    ///  The timestamp of the block in which this key image appeared
    pub timestamp: u64,
}

/// An enumeration of API calls and their arguments for use across serialization
/// boundaries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EnclaveCall {
    /// The [LedgerEnclave::enclave_init()] method.
    EnclaveInit(ResponderId, u64),

    /// The [LedgerEnclave::client_accept()] method.
    ///
    /// Process a new inbound client connection.
    ClientAccept(ClientAuthRequest),

    /// The [LedgerEnclave::client_close()] method.
    ///
    /// Tears down any in-enclave state about a client association.
    ClientClose(ClientSession),

    /// The [LedgerEnclave::get_identity()] method.
    ///
    /// Retrieves the public identity (X25519 public key) of an enclave.
    GetIdentity,

    /// The [LedgerEnclave::new_ereport()] method.
    ///
    /// Creates a new report for the enclave with the provided target info.
    NewEreport(TargetInfo),

    /// The [LedgerEnclave::verify_quote()] method.
    ///
    /// * Verifies that the Quoting Enclave is sane,
    /// * Verifies that the Quote matches the previously generated report.
    /// * Caches the quote.
    VerifyQuote(Quote, Report),

    /// The [LedgerEnclave::verify_ias_report()] method.
    ///
    /// * Verifies the signed report from IAS matches the previously received
    ///   quote,
    /// * Caches the signed report. This cached report may be overwritten by
    ///   later calls.
    VerifyReport(VerificationReport),

    /// The [LedgerEnclave::get_ias_report()] method.
    ///
    /// Retrieves a previously cached report, if any.
    GetReport,

    /// The [LedgerEnclave::get_outputs()] method.
    ///
    /// Start a new request for outputs and membership proofs from a client.
    GetOutputs(EnclaveMessage<ClientSession>),

    /// The [LedgerEnclave::get_outputs_data()] method.
    ///
    /// Re-encrypt the given outputs and proofs for transmission to a client.
    GetOutputsData(GetOutputsResponse, ClientSession),

    /// The [LedgerEnclave::client_check_key_images()] method.
    ///
    /// Start a new key image check from a client.
    CheckKeyImages(
        EnclaveMessage<ClientSession>,
        UntrustedKeyImageQueryResponse,
    ),

    /// The [LedgerEnclave::add_key_image_data()] method.
    ///
    ///  Add key image data to the ORAM.
    AddKeyImageData(Vec<KeyImageData>),
}
