// Copyright (c) 2018-2021 The MobileCoin Foundation

//! SigRL Type

use alloc::vec;

use alloc::{borrow::ToOwned, vec::Vec};
use binascii::b64decode;
use core::{
    fmt::{Display, Formatter, Result as FmtResult},
    ops::Deref,
};
use hex_fmt::HexFmt;
use mc_util_encodings::{Error as EncodingError, FromBase64};
use serde::{Deserialize, Serialize};

/// A type containing the bytes of a Signature Revocation List
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(transparent)]
pub struct SigRL {
    data: Vec<u8>,
}

impl SigRL {
    pub fn new(sigrl: &[u8]) -> Self {
        SigRL {
            data: sigrl.to_owned(),
        }
    }

    /// SigRL ptr should be the null pointer if size is 0.
    ///
    /// This is an annoying requirement of `sgx_calc_quote_size` and
    /// `sgx_get_quote`. Failure to satisfy this requirement results in
    /// `SGX_ERROR_INVALID_PARAMETER`.
    pub fn as_ptr(&self) -> *const u8 {
        if !self.data.is_empty() {
            self.data.as_ptr()
        } else {
            core::ptr::null()
        }
    }

    pub fn size(&self) -> u32 {
        self.data.len() as u32
    }
}

impl Deref for SigRL {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl Display for SigRL {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        write!(formatter, "{}", HexFmt(self))
    }
}

impl AsRef<[u8]> for SigRL {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl FromBase64 for SigRL {
    type Error = EncodingError;

    fn from_base64(s: &str) -> Result<Self, EncodingError> {
        let mut data;
        if s.is_empty() {
            // Ensure size of data remains 0 if empty string
            data = vec![];
        } else {
            data = vec![0u8; 4 * (s.len() / 3) + 4];
            b64decode(s.as_bytes(), data.as_mut_slice())?;
        }
        Ok(SigRL { data })
    }
}
