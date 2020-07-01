use core::num::ParseIntError;

use mc_crypto_keys::KeyError;
use mc_util_uri::UriParseError;

use base64::DecodeError as B64Error;
use displaydoc::Display;

/// An error that can occur when parsing one of the Url's defined here
#[derive(Clone, Eq, PartialEq, Debug, Display)]
pub enum Error {
    /// Could not parse MobUrl: {0}
    MobUrl(UriParseError),
    /// Could not parse FogUrl: {0}
    FogUrl(UriParseError),
    /// Could not parse version number: {0}
    Version(ParseIntError),
    /// Could not parse mob amount number: {0}
    Amount(ParseIntError),
    /// Could not decode path as url-safe base64: {0}
    Path(B64Error),
    /// Checksum failed in the path
    PathChecksum,
    /// Unexpected decoded url path length, should decode to 66 bytes for cryptonote keys + checksum, found: {0}
    UnexpectedUrlPathLength(usize),
    /// Could not decode fog-authority-sig as url-safe base64: {0}
    FogAuthoritySig(B64Error),
    /// Unexpected decoded fog authority sig length, expected at least 2 bytes, found: {0}
    UnexpectedFogAuthoritySigLength(usize),
    /// Checksum failed in the fog authority sig
    FogAuthoritySigChecksum,
    /// Could not decode elliptic curve point: {0}
    InvalidKey(KeyError),
}

impl From<KeyError> for Error {
    fn from(src: KeyError) -> Self {
        Self::InvalidKey(src)
    }
}
