//! This represents a versioning scheme for Ristretto-Box encrypted ciphertexts
//! that are supposed to be shooting for 128-bit security. It is intended to be
//! a wire-stable format.
//!
//! The point of the version numbers is to allow clients to decrypt arbitrarily
//! old ciphertexts from the recovery database.
//! (And also, to allow to upgrade the ingest server separately from the clients.)
//!
//! The idea here is, take one or several implementations of CryptoBox trait,
//! with FooterSize = 48, then stick two additional bytes in the footer. The
//! first is a major version (or "magic byte"), and the second is a minor version.
//! The minor version selects which algorithm we will use.
//! A major version mismatch means we can't proceed at all. This might happen
//! if we decide that the FooterSize must increase.
//!
//! Minor version mapping:
//! 0 = hkdf_blake2b_aes_128_gcm

use crate::{
    hkdf_blake2b_aes_128_gcm::RistrettoHkdfBlake2bAes128Gcm,
    traits::{CryptoBox, Error},
};

use aead::{
    generic_array::{
        arr, arr_impl,
        sequence::Concat,
        typenum::{Unsigned, U50},
        GenericArray,
    },
    Error as AeadError,
};
use alloc::vec::Vec;
use failure::Fail;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use rand_core::{CryptoRng, RngCore};

////
// CONFIGURATION
////

/// A "magic byte" value checked during this process, but not interpretted.
const MAJOR_VERSION: u8 = 0;
/// The "default" version that we would use for encryption lacking any version negotiation.
const LATEST_MINOR_VERSION: u8 = 0;
/// The versions that we would find "acceptable" during version negotiation.
/// This list allows clients and servers to be upgraded at different times.
/// Items should be removed from this list if found insecure.
const ACCEPTABLE_MINOR_VERSIONS: &[u8] = &[0];
/// The list of algos used.
/// Minor version numbers correspond to indexes into this tuple.
/// Items should NOT be removed from this list, it will break compatibility,
/// and make it impossible for users to read old data from the recovery db.
/// Note: When extending this tuple, you must add additional arms to the match
/// statements in the implementation below.
type ImplTuple = (RistrettoHkdfBlake2bAes128Gcm,);

////
// Implementation
////

/// An object implementing CryptoBox trait that calls out to one of several other
/// implementations, then attaches versioning tags. When decrypting, it interprets
/// those versioning tags.
pub struct VersionedCryptoBox {
    /// The version that this cipher object will use for encryption.
    /// Decryption will always work for any implemented scheme.
    selected_version: u8,
    /// The different implementations, represented as a tuple
    algos: ImplTuple,
}

impl VersionedCryptoBox {
    pub fn major_version() -> u8 {
        MAJOR_VERSION
    }
    /// The list of versions that are acceptable during version negotiation
    pub fn acceptable_minor_versions() -> Vec<u8> {
        ACCEPTABLE_MINOR_VERSIONS.to_vec()
    }
    /// Called by a client to select an acceptable version based on what a server adverstised
    pub fn select_version(others_acceptable_versions: &[u8]) -> Result<Self, VersionError> {
        Self::acceptable_minor_versions()
            .iter()
            .filter(|x| others_acceptable_versions.contains(x))
            .max()
            .ok_or(VersionError::NoAcceptableVersions)
            .map(|ver| Self {
                selected_version: *ver,
                algos: Default::default(),
            })
    }
}

/// Default to the latest version for encryption, lacking any version negotiation info
/// This is typical in the ingest node, which cannot negotiate with all clients.
impl Default for VersionedCryptoBox {
    fn default() -> Self {
        Self {
            selected_version: LATEST_MINOR_VERSION,
            algos: Default::default(),
        }
    }
}

impl CryptoBox for VersionedCryptoBox {
    // The footer size is:
    // 32 for curve point
    // 16 for mac, at 128 bit sec level
    // 2 for version info
    type FooterSize = U50;

    // Choose the algo based on self.selected_version
    fn encrypt_in_place_detached<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        key: &RistrettoPublic,
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::FooterSize>, AeadError> {
        // Match is used because we cannot index into a tuple with run-time values,
        // but there might be some macro trickery that could clean this up more.
        // If we want to be generic over rng, we cannot use arrays of fn ptr's here.
        let footer = match self.selected_version {
            // Add additional arms to this match if adding new versions
            0u8 => self.algos.0.encrypt_in_place_detached(rng, key, buffer)?,
            _ => panic!(
                "self.selected_version is holding an illegal value: {}",
                self.selected_version
            ),
        };
        Ok(footer.concat(arr![u8; MAJOR_VERSION, self.selected_version]))
    }

    // Choose the algo based on the version data in the ciphertext
    fn decrypt_in_place_detached(
        &self,
        key: &RistrettoPrivate,
        footer: &GenericArray<u8, Self::FooterSize>,
        buffer: &mut [u8],
    ) -> Result<(), Error> {
        // Note: When generic_array is upreved, this can be tidier using this:
        // https://docs.rs/generic-array/0.14.1/src/generic_array/sequence.rs.html#302-320
        // For now we have to split as a slice, then convert back to Generic Array.
        let (footer, version_data) = footer.split_at(<Self as CryptoBox>::FooterSize::USIZE - 2);
        let footer = GenericArray::from_slice(footer);
        if MAJOR_VERSION != version_data[0] {
            return Err(Error::WrongMagicBytes);
        }
        match version_data[1] {
            // Add additional arms to this match if adding new versions
            0u8 => self.algos.0.decrypt_in_place_detached(key, footer, buffer),
            _ => Err(Error::UnknownAlgorithm(version_data[1] as usize)),
        }
    }
}

#[derive(Fail, Debug)]
pub enum VersionError {
    #[fail(display = "No mutually acceptable CryptoBox versions could be found")]
    NoAcceptableVersions,
}
