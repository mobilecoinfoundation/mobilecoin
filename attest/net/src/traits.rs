// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A collection of generic traits for remote attestation providers

use displaydoc::Display;
use mc_attest_core::{EpidGroupId, IasNonce, Quote, QuoteError, SigRL, VerificationReport};
use mc_util_encodings::Error as EncodingError;
use reqwest::{header::ToStrError, Error as ReqwestError};
use std::result::Result as StdResult;

/// An enumeration of potential client errors when communicating with a
/// remote attestation service.
#[derive(Debug, Display)]
pub enum Error {
    /// There was an error while handling a quote object
    Quote(QuoteError),
    /// There was an error making a request to the IAS API: {0}
    Reqwest(ReqwestError),
    /// There was an converting a response received from the IAS API: {0}
    Encoding(EncodingError),
    /// There is no signature header in the verification report response
    MissingSignatureError,
    /// A header header string could not be parsed: {0}
    ToStrError(ToStrError),
    /**
     * The verification report response did not include any signing
     * certificates
     */
    MissingSigningCertsError,
    /**
     * The verification report response did not contain valid PEM for it's
     * signing certificates
     */
    BadSigningCertsError,
    /// The given API key is not a valid header value
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
