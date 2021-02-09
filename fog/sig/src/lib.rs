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
//! Fog authority signatures are created by the owner of an account, in order to
//! delegate transaction monitoring to an enclave using the on-chain fog
//! accounts hints. In order to accomplish this, the user signs the  DER-encoded
//! bytes of a `subjectPublicKeyInfo` X509 structure from the root certificate
//! of their fog operator.
//!
//! The operator, in turn, creates one or more intermediate certificates, which
//! in turn issue Ed25519 signing certificates to a report server.
//!
//! # Fog Report Signatures
//!
//! A fog report server uses the signing key and certificate provided by the fog
//! operator in order to cryptographically sign a list of IAS verification
//! report structures created by ingest nodes. This resulting data (chain,
//! signature, and reports) is then returned from the fog report server to a
//! senders when they want to send coins to the destination account owner.
//!
//! # Sender Verification
//!
//! The sender must verify the user's signature over the root certificate, the
//! certificate chain to the report server, and the report server's signature
//! over the report list, in order to determine which
//! [`VerificationReport`](mc_attest_core::VerificationReport) belongs
//! to the destination fog ingest enclave.
//!
//! At this point, the sender has verified that the account owner has delegated
//! transaction monitoring authority to a given ingest enclave.
//!
//! # Future Work
//!
//! The most basic missing functionality here is support for RSA leaf
//! certificates. This, in turn, will end up blocking on a nice rust
//! implementation of the RSA algorithm.
//!
//! Additionally, it would be nice for this crate to function in an enclave in
//! order to support enclaves for clients and report servers.

mod authority;
mod report;
mod scheme;

pub use crate::{
    authority::{
        context as authority_context, Error as AuthorityError, Signer as AuthoritySigner,
        Verifier as AuthorityVerifier,
    },
    report::{context as report_context, Signer as ReportSigner, Verifier as ReportVerifier},
    scheme::{Error as FogSignatureError, Verifier as FogSignatureVerifier},
};
