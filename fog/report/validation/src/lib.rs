//! Logic for representing fog public keys from the fog-report server
//! that have been fully validated, and the associated metadata.

// Copyright (c) 2018-2020 MobileCoin Inc.

#![deny(missing_docs)]
#![cfg_attr(not(any(test, feature = "automock")), no_std)]

extern crate alloc;

use alloc::{
    collections::{btree_map::Entry, BTreeMap},
    string::{String, ToString},
};
use core::fmt::{Debug, Display};
use displaydoc::Display;
use mc_account_keys::PublicAddress;
use mc_crypto_keys::RistrettoPublic;

#[cfg(any(test, feature = "automock"))]
use mockall::*;

/// Data structure for fog-ingest report validation
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
    /// Error type returned by the fog pubkey resolver
    type Error: Display + Debug;
    /// Fetch and validate a fog public key, given a recipient's public address
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

/// Represents a set of fully validated fog public keys
///
/// These can be fetched before building a transaction, then the rest of the
/// transaction building process can happen offline.
#[derive(Default, Debug)]
pub struct FullyValidatedFogPubkeys {
    /// Map from fog_url, fog_report_id strings to fully validated pubkeys
    keys: BTreeMap<(String, String), FullyValidatedFogPubkey>,
}

impl FullyValidatedFogPubkeys {
    /// Check if we have a fog pubkey needed for a given recipient.
    /// If so, do nothing.
    /// If not, try to fetch one using the resolver.
    pub fn add_key_for_recipient<R: FogPubkeyResolver>(
        &mut self,
        resolver: &R,
        recipient: &PublicAddress,
    ) -> Result<(), R::Error> {
        if let Some(table_key) = self.table_key(recipient) {
            match self.keys.entry(table_key) {
                Entry::Occupied(_) => {}
                Entry::Vacant(ent) => {
                    ent.insert(resolver.get_fog_pubkey(recipient)?);
                }
            }
        }
        Ok(())
    }

    /// Alternative to add_key_for_recipient, this may be helpful for SDK code which doesn't want to make blocking calls into rust.
    pub fn add_key(&mut self, report_url: String, validated_key: FullyValidatedFogPubkey) {
        self.keys.insert(
            (report_url, validated_key.fog_report_id.clone()),
            validated_key,
        );
    }

    /// Construct the key to use in the table for given public address
    /// Returns None if the public address doesn't have a fog report url.
    fn table_key(&self, addr: &PublicAddress) -> Option<(String, String)> {
        addr.fog_report_url().map(|url| {
            (
                url.to_string(),
                addr.fog_report_id().unwrap_or("").to_string(),
            )
        })
    }

    /// Get the smallest pubkey_expiry value of any of these fog pubkeys.
    /// Returns u64::MAX if there are no fog pubkeys present.
    pub fn smallest_pubkey_expiry_value(&self) -> u64 {
        self.keys.values().fold(u64::MAX, |cur_min, key| {
            core::cmp::min(cur_min, key.pubkey_expiry)
        })
    }
}

impl FogPubkeyResolver for FullyValidatedFogPubkeys {
    type Error = FogPubkeyError;

    fn get_fog_pubkey(
        &self,
        recipient: &PublicAddress,
    ) -> Result<FullyValidatedFogPubkey, Self::Error> {
        if let Some(table_key) = self.table_key(recipient) {
            if let Some(result) = self.keys.get(&table_key) {
                Ok(result.clone())
            } else {
                Err(FogPubkeyError::FogPubkeyNotPrefetched(
                    table_key.0,
                    table_key.1,
                ))
            }
        } else {
            Err(FogPubkeyError::NoFogReportUrl)
        }
    }
}

/// An error that can occur when trying to get a fog pubkey from the FullyValidatedFogPubkeys set
#[derive(Display, Debug)]
pub enum FogPubkeyError {
    /// FogPubkey was not prefetched for url = {0}, report_id = {1}
    FogPubkeyNotPrefetched(String, String),
    /// Address has no fog_report_url, cannot fetch fog pubkey
    NoFogReportUrl,
}
