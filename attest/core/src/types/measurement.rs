// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains the wrapper types for an sgx_measurement_t
//!
//! Different types are used for MrSigner and MrEnclave to prevent misuse.

use crate::{
    impl_base64str_for_bytestruct, impl_hexstr_for_bytestruct, impl_sgx_newtype_for_bytestruct,
};
use core::fmt::{Display, Formatter, Result as FmtResult};
use mc_sgx_types::{sgx_measurement_t, SGX_HASH_SIZE};
use serde::{Deserialize, Serialize};

/// An opaque type for MRENCLAVE values
///
/// A MRENCLAVE value is a chained cryptographic hash of the signed
/// enclave binary (.so), and the results of the page initialization
/// steps which created the enclave's pages.
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct MrEnclave(sgx_measurement_t);

impl From<[u8; SGX_HASH_SIZE]> for MrEnclave {
    fn from(m: [u8; SGX_HASH_SIZE]) -> Self {
        MrEnclave(sgx_measurement_t { m })
    }
}

/// An opaque type for MRSIGNER values.
///
/// A MRSIGNER value is a cryptographic hash of the public key an enclave
/// was signed with.
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct MrSigner(sgx_measurement_t);

impl From<[u8; SGX_HASH_SIZE]> for MrSigner {
    fn from(m: [u8; SGX_HASH_SIZE]) -> Self {
        MrSigner(sgx_measurement_t { m })
    }
}

impl_sgx_newtype_for_bytestruct! {
    MrEnclave, sgx_measurement_t, SGX_HASH_SIZE, m;
    MrSigner, sgx_measurement_t, SGX_HASH_SIZE, m;
}

impl_base64str_for_bytestruct! {
    MrEnclave, SGX_HASH_SIZE, m;
    MrSigner, SGX_HASH_SIZE, m;
}

impl_hexstr_for_bytestruct! {
    MrEnclave, SGX_HASH_SIZE, m;
    MrSigner, SGX_HASH_SIZE, m;
}

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
            Measurement::MrEnclave(e) => write!(f, "MRENCLAVE: {}", e),
            Measurement::MrSigner(s) => write!(f, "MRSIGNER: {}", s),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_util_serial::{deserialize, serialize};

    #[test]
    fn test_mrenclave_serde() {
        let mr_value = sgx_measurement_t {
            m: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        };
        let mrenclave: MrEnclave = mr_value.into();
        let mrser = serialize(&mrenclave).expect("Could not serialize MrEnclave.");
        let mrdeser: MrEnclave = deserialize(&mrser).expect("Could not deserialize MrEnclave.");
        assert_eq!(mrenclave, mrdeser);
    }

    #[test]
    fn test_mrsigner_serde() {
        let mr_value = sgx_measurement_t {
            m: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        };
        let mrsigner: MrSigner = mr_value.into();
        let mrser = serialize(&mrsigner).expect("Could not serialize MrSigner.");
        let mrdeser: MrSigner = deserialize(&mrser).expect("Could not deserialize MrSigner.");
        assert_eq!(mrsigner, mrdeser);
    }
}
