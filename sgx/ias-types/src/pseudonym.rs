// Copyright (c) 2018-2020 MobileCoin Inc.

//! EPID Pseudonym

use binascii::b64decode;
use core::{
    cmp::Ordering,
    fmt::{Debug, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use mc_sgx_core_types::_macros::EncodingError;
use mc_util_encodings::FromBase64;

const EPID_PSEUDONYM_B_SIZE: usize = 64;
const EPID_PSEUDONYM_K_SIZE: usize = 64;

/// The length of the EPID Pseudonym, in bytes.
pub const EPID_PSEUDONYM_SIZE: usize = EPID_PSEUDONYM_B_SIZE + EPID_PSEUDONYM_K_SIZE;

/// A linkable EPID signature, used to link a quote to a given piece of
/// hardware.
///
/// When using linkable quotes, the report from IAS will contain this
/// structure, encoded as base64 bytes. If a requester requests a host
/// attest again, the EpidPseudonym should be unchanged. Pseudonym
/// change detection can be used to warn a node operator that a peer's
/// hardware has changed. If this change is unexpected, this indicates
/// an area of inquiry for the operator to chase down.
//
// This (AFAICT) comes from the [EPID signature scheme](https://eprint.iacr.org/2009/095.pdf)
// [presentation](https://csrc.nist.gov/csrc/media/events/meeting-on-privacy-enhancing-cryptography/documents/brickell.pdf),
// "K = B**f", or "pseudonym = named_base ** machine_privkey".
//
// Per the IAS API documentation:
//
// > Byte array representing EPID Pseudonym that consists of the
// > concatenation of EPID B (64 bytes) & EPID K (64 bytes) components
// > of EPID signature. If two linkable EPID signatures for an EPID Group
// > have the same EPID Pseudonym, the two signatures were generated
// > using the same EPID private key. This field is encoded using Base 64
// > encoding scheme.
//
#[repr(transparent)]
#[derive(Clone)]
pub struct EpidPseudonym([u8; EPID_PSEUDONYM_SIZE]);

impl EpidPseudonym {
    /// Retrieve the "B" value for the pseudonym
    pub fn b(&self) -> &[u8] {
        &self.0[..EPID_PSEUDONYM_B_SIZE]
    }

    /// Retrieve the "K" value for the pseudonym
    pub fn k(&self) -> &[u8] {
        &self.0[EPID_PSEUDONYM_K_SIZE..(EPID_PSEUDONYM_B_SIZE + EPID_PSEUDONYM_K_SIZE)]
    }
}

impl Debug for EpidPseudonym {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "EpidPseudonym: {:?}", &self.0[..])
    }
}

impl Default for EpidPseudonym {
    fn default() -> Self {
        Self([0u8; EPID_PSEUDONYM_SIZE])
    }
}

impl Eq for EpidPseudonym {}

impl FromBase64 for EpidPseudonym {
    type Error = EncodingError;

    fn from_base64(src: &str) -> Result<Self, EncodingError> {
        let mut retval = Self::default();
        b64decode(src.as_bytes(), &mut retval.0[..])?;
        Ok(retval)
    }
}

impl Hash for EpidPseudonym {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "EpidPseudonym".hash(state);
        self.0[..].hash(state);
    }
}

impl Ord for EpidPseudonym {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0[..].cmp(&other.0[..])
    }
}

impl PartialEq for EpidPseudonym {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl PartialOrd for EpidPseudonym {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
