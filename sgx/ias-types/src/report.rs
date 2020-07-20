// Copyright (c) 2018-2020 MobileCoin Inc.

//! IAS Report structure

use alloc::{string::String, vec::Vec};
#[cfg(feature = "use_prost")]
use prost::Message;

/// A verification report returned from IAS.
#[cfg_attr(feature = "use_prost", derive(Message))]
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Report {
    /// A signature over the HTTP body string using a public key contained in
    /// the chain
    #[cfg_attr(feature = "use_prost", prost(bytes, required))]
    pub sig: Vec<u8>,

    /// A set of of DER-encoded public-key certificates which contain the
    /// elements of a certificate chain from the trusted Intel root
    /// authority to the signing public key, albeit in arbitrary order.
    #[cfg_attr(feature = "use_prost", prost(bytes, repeated))]
    pub chain: Vec<Vec<u8>>,

    /// The JSON-formatted HTTP body text, encoded as a UTF-8 string.
    #[cfg_attr(feature = "use_prost", prost(string))]
    pub http_body: String,
}
