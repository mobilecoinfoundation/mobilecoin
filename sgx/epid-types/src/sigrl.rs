// Copyright (c) 2018-2020 MobileCoin Inc.

//! Traits and support for EPID-based remote attestation.

use alloc::vec;

use alloc::vec::Vec;
use binascii::b64decode;
use core::fmt::{Display, Formatter, Result as FmtResult};
use hex_fmt::HexFmt;
use mc_sgx_core_types::_macros::base64_buffer_size;
use mc_util_encodings::{Error as EncodingError, FromBase64};
use serde::{Deserialize, Serialize};

/// A structure containing a signature revocation list.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SignatureRevocationList(Vec<u8>);

impl AsRef<[u8]> for SignatureRevocationList {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<&[u8]> for SignatureRevocationList {
    fn from(src: &[u8]) -> SignatureRevocationList {
        Self::from(Vec::from(src))
    }
}

impl From<Vec<u8>> for SignatureRevocationList {
    fn from(src: Vec<u8>) -> SignatureRevocationList {
        Self(src)
    }
}

impl Display for SignatureRevocationList {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", HexFmt(self))
    }
}

impl FromBase64 for SignatureRevocationList {
    type Error = EncodingError;

    fn from_base64(s: &str) -> Result<Self, EncodingError> {
        let buffer_len = base64_buffer_size(s.as_bytes().len());
        let mut data = vec![0u8; buffer_len];

        let used = {
            let buffer = b64decode(s.as_bytes(), data.as_mut_slice())?;
            buffer.len()
        };
        data.truncate(used);

        Ok(Self::from(data))
    }
}
