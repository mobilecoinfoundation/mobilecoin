// Copyright (c) 2018-2021 The MobileCoin Foundation

#![cfg_attr(not(any(test, feature = "automock")), no_std)]

extern crate alloc;

use alloc::string::String;
use core::fmt::{Debug, Display};
use mc_account_keys::PublicAddress;
use mc_crypto_keys::RistrettoPublic;

#[cfg(any(test, feature = "automock"))]
use mockall::*;

pub mod ingest_report;

/// Represents a fog public key validated to use for creating encrypted fog hints.
/// This object should be constructed only when the IAS report has been validated.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct IasValidatedFogPubkey(pub RistrettoPublic);

impl AsRef<RistrettoPublic> for IasValidatedFogPubkey {
    fn as_ref(&self) -> &RistrettoPublic {
        &self.0
    }
}

/// Fully resolves a public address to a fully validated fog public key structure,
/// including all the data from the report server.
/// This interface may include grpc and so likely cannot be implemented in a way
/// that is safe for libmobilecoin / asynchronous java requirements.
#[cfg_attr(any(test, feature = "automock"), automock(type Error = String;))]
pub trait FogPubkeyResolver {
    type Error: Display + Debug;
    fn get_fog_pubkey(
        &self,
        recipient: &PublicAddress,
    ) -> Result<FullyValidatedFogPubkey, Self::Error>;
}

/// Represents a fog public key validated to use for creating encrypted fog hints.
/// This object should be constructed only when the IAS report has been validated,
/// and the chain of trust from the connection has been validated, and the
/// the fog user's fog_authority_fingerprint_sig over the fingerprints in the signature chain
/// has been validated for at least one fingerprint.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct FullyValidatedFogPubkey {
    /// The fog_report_id value from the fog report.Report proto structure
    pub fog_report_id: String,
    /// The ristretto curve point which was extracted from the IAS report additional data
    /// after validation. This is the encryption key used to create encrypted fog hints.
    /// The corresponding private key lives only in SGX ingest nodes.
    pub pubkey: RistrettoPublic,
    /// The pubkey_expiry value is the latest block that fog-service promises
    /// that is valid to encrypt fog hints using this key for.
    /// The client should obey this limit by not setting tombstone block for a
    /// transaction larger than this limit if the fog pubkey is used.
    pub pubkey_expiry: u64,
}
