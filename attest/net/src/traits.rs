// Copyright (c) 2018-2020 MobileCoin Inc.

//! A collection of generic traits for remote attestation providers

use failure::Fail;
use mc_attest_core::{EpidGroupId, IasNonce, Quote, QuoteError, SigRL, VerificationReport};
use mc_util_encodings::Error as EncodingError;
use reqwest::{header::ToStrError, Error as ReqwestError};
use std::result::Result as StdResult;

/// An enumeration of potential client errors when communicating with a
/// remote attestation service.
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "There was an error while handling a quote object")]
    Quote(QuoteError),
    #[fail(display = "There was an error making a request to the IAS API: {}", _0)]
    Reqwest(ReqwestError),
    #[fail(
        display = "There was an converting a response received from the IAS API: {}",
        _0
    )]
    Encoding(EncodingError),
    #[fail(display = "There is no signature header in the verification report response")]
    MissingSignatureError,
    #[fail(display = "A header header string could not be parsed: {}", _0)]
    ToStrError(ToStrError),
    #[fail(display = "The verification report response did not include any signing certificates")]
    MissingSigningCertsError,
    #[fail(
        display = "The verification report response did not contain valid PEM for it's signing certificates"
    )]
    BadSigningCertsError,
    #[fail(display = "The given API key is not a valid header value")]
    BadApiKey,
}

/// Automatically wrap mc_util_encodings::EncodingError into an RaClientError.
impl From<EncodingError> for Error {
    fn from(src: EncodingError) -> Error {
        Error::Encoding(src)
    }
}

/// Automatically wrap an mc_attest_core::QuoteError into a RA Client error
impl From<QuoteError> for Error {
    fn from(src: QuoteError) -> Error {
        Error::Quote(src)
    }
}

/// Automatically wrap reqwest::Error into an RaClientError.
impl From<ReqwestError> for Error {
    fn from(src: ReqwestError) -> Error {
        Error::Reqwest(src)
    }
}

/// Automatically wrap reqwest::header::ToStrError into an RaClientError.
impl From<ToStrError> for Error {
    fn from(src: ToStrError) -> Error {
        Error::ToStrError(src)
    }
}

/// Syntactic sugar for a result with an RaClientError.
pub type Result<T> = StdResult<T, Error>;

/// A trait for generic remote attesation service clients.
///
/// It is assumed this will be updated/changed for DCAP.
pub trait RaClient: Clone + Send + Sized + Sync {
    fn new(credentials: &str) -> Result<Self>;

    /// Retrieve the SigRL for the given EPID Group ID.
    fn get_sigrl(&self, gid: EpidGroupId) -> Result<SigRL>;

    /// Submit the given quote to IAS and parse the response into a
    /// VerificationReport.
    fn verify_quote(
        &self,
        quote: &Quote,
        ias_nonce: Option<IasNonce>,
    ) -> Result<VerificationReport>;
}
