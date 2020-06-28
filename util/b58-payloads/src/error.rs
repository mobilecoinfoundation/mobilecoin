//! Error types

use failure::Fail;
use mc_crypto_keys::KeyError;
use mc_util_uri::UriParseError;
use std::string::FromUtf8Error;

#[derive(Clone, Debug, Eq, PartialEq, Fail)]
pub enum Error {
    /// A parameter has fewer bytes than expected.
    #[fail(display = "A parameter is too small: {:?}", _0)]
    TooFewBytes(String),

    /// A parameter has more bytes than expected.
    #[fail(display = "A parameter is too big: {:?}", _0)]
    TooManyBytes(String),

    /// Encoded string is the wrong type.
    #[fail(display = "Encoded string is the wrong type")]
    TypeMismatch,

    /// Checksum for payload is incorrect.
    #[fail(display = "Checksum for payload is incorrect")]
    ChecksumError,

    /// Unable to parse a UTF-8 string.
    #[fail(display = "Unable to parse UTF-8 string")]
    Utf8ParsingError,

    /// Unable to convert string to a URL.
    #[fail(display = "Invalid fog service URL: {}", _0)]
    FogUrlParsingError(UriParseError),

    /// A public key is not a valid Ristretto point.
    #[fail(display = "Invalid public key: {:?}", _0)]
    KeyError(KeyError),

    /// The address is not a valid base58 string.
    #[fail(display = "Invalid base58 string")]
    Base58DecodingError,

    /// Unable to parse PayloadType.
    #[fail(display = "Unable to parse a PayloadType enum")]
    PayloadTypeParsingError,
}

impl From<KeyError> for Error {
    fn from(src: KeyError) -> Self {
        Error::KeyError(src)
    }
}

impl From<bs58::decode::Error> for Error {
    fn from(_: bs58::decode::Error) -> Self {
        Error::Base58DecodingError
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_: FromUtf8Error) -> Self {
        Error::Utf8ParsingError
    }
}
