// Copyright (c) 2018-2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]

use mc_attest_core::IsvSvn;
use mc_attestation_verifier::{TrustedIdentity, TrustedMrSignerIdentity};
use mc_sgx_css::Signature;

pub fn sigstruct() -> Signature {
    Signature::try_from(&include_bytes!(env!("MCBUILD_ENCLAVE_CSS_PATH"))[..])
        .expect("Could not read ingest enclave metadata")
}

pub const HARDENING_ADVISORIES: &[&str] = &["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"];

pub fn mr_signer_identity(override_minimum_svn: Option<IsvSvn>) -> TrustedIdentity {
    let signature = sigstruct();

    let mr_signer = TrustedMrSignerIdentity::new(
        signature.mrsigner().into(),
        signature.product_id(),
        override_minimum_svn.unwrap_or_else(|| signature.version()),
        [] as [&str; 0],
        HARDENING_ADVISORIES,
    );
    mr_signer.into()
}
