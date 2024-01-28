// Copyright (c) 2018-2022 The MobileCoin Foundation

//! This module contains the wrapper types for an sgx_measurement_t
//!
//! Different types are used for MrSigner and MrEnclave to prevent misuse.

use core::fmt::{Display, Formatter, Result as FmtResult};
use mc_sgx_core_types::{MrEnclave, MrSigner};
use serde::{Deserialize, Serialize};

/// An enumeration of measurement options, mainly useful for describing
/// enclave-vs-author attestation policy.
#[derive(Clone, Copy, Debug, Deserialize, Hash, Eq, Ord, PartialOrd, PartialEq, Serialize)]
pub enum Measurement {
    MrEnclave(MrEnclave),
    MrSigner(MrSigner),
}

impl From<MrEnclave> for Measurement {
    fn from(mr_enclave: MrEnclave) -> Self {
        Measurement::MrEnclave(mr_enclave)
    }
}

impl From<MrSigner> for Measurement {
    fn from(mr_signer: MrSigner) -> Self {
        Measurement::MrSigner(mr_signer)
    }
}

impl PartialEq<MrEnclave> for Measurement {
    fn eq(&self, other: &MrEnclave) -> bool {
        match self {
            Measurement::MrEnclave(enclave) => enclave == other,
            _ => false,
        }
    }
}

impl PartialEq<MrSigner> for Measurement {
    fn eq(&self, other: &MrSigner) -> bool {
        match self {
            Measurement::MrSigner(signer) => signer == other,
            _ => false,
        }
    }
}

impl Display for Measurement {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Measurement::MrEnclave(e) => write!(f, "MRENCLAVE: {e}"),
            Measurement::MrSigner(s) => write!(f, "MRSIGNER: {s}"),
        }
    }
}
