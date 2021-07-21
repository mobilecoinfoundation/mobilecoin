// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains code intended to operate within an SGX enclave.

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

use alloc::vec;

use alloc::vec::Vec;
use core::convert::TryFrom;
use displaydoc::Display;
use mc_attest_core::{
    IntelSealed, ParseSealedError, Report, ReportData, Sealed, SgxError, SgxResult, TargetInfo,
};
use mc_sgx_types::sgx_status_t;
use prost::Message;

/// Methods on the `mc_attest_core::Report` object which are only usable inside
/// a running SGX enclave.
pub trait EnclaveReport: Sized {
    /// Create a new EREPORT for the specified target enclave, with the given
    /// user data.
    fn new(target_info: Option<&TargetInfo>, report_data: Option<&ReportData>) -> SgxResult<Self>;

    /// Verify a report was created for the currently running enclave.
    fn verify(&self) -> SgxResult<()>;
}

/// Implement Reportable interface
impl EnclaveReport for Report {
    fn new(target_info: Option<&TargetInfo>, report_data: Option<&ReportData>) -> SgxResult<Self> {
        Ok(mc_sgx_compat::report(
            target_info.map(|x| x.as_ref()),
            report_data.map(|x| x.as_ref()),
        )
        .map(Report::from)?)
    }

    fn verify(&self) -> SgxResult<()> {
        Ok(mc_sgx_compat::verify_report(self.as_ref())?)
    }
}

/// High level API for sealing and unsealing objects based on Sealed trait
/// and sealed blob

/// Seal a Sealed::Source object and return a Sealed
pub fn seal<S: Sealed>(obj: &S::Source) -> Result<S, S::Error> {
    let mut buf = Vec::new();
    obj.encode(&mut buf)
        .expect("encoding to an unbounded buffer should not fail");
    let mac_txt = S::compute_mac_txt(obj);
    let blob = IntelSealed::seal_raw(&buf[..], mac_txt.as_ref())
        .map_err(error_conversion_helper::<S::Error>)?;
    S::validate_mac_txt(blob)
}

/// Unseal a Sealed object and return a Sealed::Source
pub fn unseal<S: Sealed>(obj: &S) -> Result<S::Source, UnsealingError> {
    let (encoded, _) = <S as AsRef<IntelSealed>>::as_ref(obj).unseal_raw()?;
    Ok(S::Source::decode(&encoded[..])?)
}

/// Blob sealing and unsealing API
/// This is a trait because reviewers desired that `seal_raw` and `unseal_raw`
/// should be member functions of IntelSealed but they cannot be in the same
/// crate.
pub trait SealAlgo: Sized {
    /// Takes plaintext and optional additional text that is under the mac,
    /// produces sealed blob
    fn seal_raw(plaintext: &[u8], additional_mac_txt: &[u8]) -> Result<Self, IntelSealingError>;
    /// Takes a sealed blob, reproduces the plaintext and the additional mac
    /// text, in that order
    fn unseal_raw(&self) -> SgxResult<(Vec<u8>, Vec<u8>)>;
}

impl SealAlgo for IntelSealed {
    fn seal_raw(plaintext: &[u8], additional_mac_txt: &[u8]) -> Result<Self, IntelSealingError> {
        let result_len =
            mc_sgx_compat::calc_sealed_data_size(plaintext.len(), additional_mac_txt.len())?;
        let mut result = vec![0u8; result_len as usize];
        mc_sgx_compat::seal_data(plaintext, additional_mac_txt, &mut result[..])?;

        Ok(Self::try_from(result)?)
    }
    fn unseal_raw(&self) -> SgxResult<(Vec<u8>, Vec<u8>)> {
        let (plaintext_len, mac_txt_len) = mc_sgx_compat::get_sealed_payload_sizes(self.as_ref())?;
        let mut plaintext = vec![0u8; plaintext_len as usize];
        let mut mac_txt = vec![0u8; mac_txt_len as usize];
        mc_sgx_compat::unseal_data(self.as_ref(), &mut plaintext[..], &mut mac_txt[..])?;
        Ok((plaintext, mac_txt))
    }
}

/// Represents an error that can occur during sealing an IntelSealed blob
/// This is the error type of seal_raw
#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum IntelSealingError {
    /// SGX error: {0}
    Sgx(SgxError),
    /// Bad sealed format: {0}
    SealFormat(ParseSealedError),
}

impl From<SgxError> for IntelSealingError {
    fn from(src: SgxError) -> Self {
        Self::Sgx(src)
    }
}

impl From<sgx_status_t> for IntelSealingError {
    fn from(src: sgx_status_t) -> Self {
        Self::Sgx(SgxError::from(src))
    }
}

impl From<ParseSealedError> for IntelSealingError {
    fn from(src: ParseSealedError) -> Self {
        Self::SealFormat(src)
    }
}

// allow conversion to a user defined type (Sealed::Error) that is general
// enough to hold SgxError and ParseSealedError
fn error_conversion_helper<T: From<SgxError> + From<ParseSealedError>>(
    src: IntelSealingError,
) -> T {
    match src {
        IntelSealingError::Sgx(e) => T::from(e),
        IntelSealingError::SealFormat(e) => T::from(e),
    }
}

/// Represents an error that can occur during unsealing
#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum UnsealingError {
    /// SGX error: {0}
    SgxError(SgxError),
    /// Prost decode error: {0}
    Decode(prost::DecodeError),
}

impl From<prost::DecodeError> for UnsealingError {
    fn from(src: prost::DecodeError) -> Self {
        Self::Decode(src)
    }
}

impl From<SgxError> for UnsealingError {
    fn from(src: SgxError) -> Self {
        Self::SgxError(src)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealing_round_trip(plaintext: &[u8], mac_txt: &[u8]) {
        let result = IntelSealed::seal_raw(plaintext, mac_txt).unwrap();
        let (a, b) = result.unseal_raw().unwrap();
        assert_eq!(&a[..], plaintext);
        assert_eq!(&b[..], mac_txt);
    }

    #[test]
    fn sealing_round_trip_tests() {
        sealing_round_trip(b"foo", b"bar");
        sealing_round_trip(b"baz", &[]);
    }

    #[test]
    fn expected_failure() {
        // <3 arrested development
        assert!(IntelSealed::try_from(&b"LUCILLE"[..]).is_err());

        let mut large_blob: Vec<u8> = Default::default();
        for _ in 0..512 {
            large_blob.extend(b"LUCILLE");
        }
        assert!(IntelSealed::try_from(large_blob).is_err());
    }
}
