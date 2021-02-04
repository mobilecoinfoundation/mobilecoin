// Copyright 2018-2021 The MobileCoin Foundation

//! This crate provides new traits to provide the following functionality:
//!
//!  1. Allow a recipient to sign a Fog Authority (subjectPublicKeyInfo)
//!  1. Allow the fog report server to sign a list of responses.
//!  1. Allow a sender to verify and extract the ingest key from a user's
//!     PublicAddress and a ReportResponse object(s).
//!
//! # Fog Authority Signatures
//!
//! Fog authorities are created by signing the DER-encoded bytes of the
//! `subjectPublicKeyInfo` structure within the a Fog operator's root authority
//! certificate.

mod authority;

pub use authority::{context, Signer as AuthoritySigner, Verifier as AuthorityVerifier};
