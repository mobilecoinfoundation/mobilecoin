// Copyright (c) 2018-2020 MobileCoin Inc.

//! IAS Report structure

use alloc::{string::String, vec::Vec};
use core::fmt::Debug;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A verification report returned from IAS.
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Report {
    /// A signature over the HTTP body string using a public key contained in the chain
    pub sig: Vec<u8>,

    /// A set of of DER-encoded public-key certificates which contain the elements of a certificate
    /// chain from the trusted Intel root authority to the signing public key, albeit in arbitrary
    /// order.
    pub chain: Vec<Vec<u8>>,

    /// The JSON-formatted HTTP body text, encoded as a UTF-8 string.
    pub http_body: String,
}
