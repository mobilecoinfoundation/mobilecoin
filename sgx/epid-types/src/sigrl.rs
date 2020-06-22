// Copyright (c) 2018-2020 MobileCoin Inc.

//! Traits and support for EPID-based remote attestation.

use alloc::vec::Vec;
use core::fmt::{Display, Formatter, Result as FmtResult};
use hex::FromHex;
use hex_fmt::HexFmt;
use mc_util_encodings::{Error as EncodingError, FromBase64};
#[cfg(feature = "use_prost")]
use prost::Message;
#[cfg(feature = "use_serde")]
use serde::{Deserialize, Serialize};

/// A structure containing a signature revocation list.
#[cfg_attr(feature = "use_prost", derive(Message))]
#[cfg_attr(feature = "use_serde", derive(Deserialize, Serialize))]
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SignatureRevocationList {
    #[prost(bytes, tag = "1")]
    data: Vec<u8>,
}

impl AsRef<[u8]> for SignatureRevocationList {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl From<&[u8]> for SignatureRevocationList {
    fn from(src: &[u8]) -> SignatureRevocationList {
        Self::from(Vec::from(src))
    }
}

impl From<Vec<u8>> for SignatureRevocationList {
    fn from(data: Vec<u8>) -> SignatureRevocationList {
        Self { data }
    }
}

impl Display for SignatureRevocationList {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", HexFmt(self))
    }
}

impl FromBase64 for SignatureRevocationList {
    type Error = EncodingError;

    fn from_base64(s: &str) -> Result<Self, Self::Error> {
        Ok(Self::from(base64::decode(s)?))
    }
}

impl FromHex for SignatureRevocationList {
    type Error = EncodingError;

    fn from_hex<H: AsRef<[u8]>>(data: H) -> Result<Self, Self::Error> {
        Ok(Self::from(hex::decode(data)?))
    }
}
