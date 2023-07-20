// Copyright (c) 2018-2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]

use mc_attest_core::SecurityVersion;
use mc_attest_verifier::{MrEnclaveVerifier, MrSignerVerifier};
use mc_attestation_verifier::{Advisories, AdvisoryStatus};
use mc_sgx_css::Signature;

pub fn sigstruct() -> Signature {
    Signature::try_from(&include_bytes!(env!("MCBUILD_ENCLAVE_CSS_PATH"))[..])
        .expect("Could not read measurement signature")
}

pub const HARDENING_ADVISORIES: &[&str] = &["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"];

pub fn get_mr_signer_verifier(override_minimum_svn: Option<SecurityVersion>) -> MrSignerVerifier {
    let advisories: Advisories =
        Advisories::new(HARDENING_ADVISORIES, AdvisoryStatus::SWHardeningNeeded);
    let signature = sigstruct();
    let mut mr_signer_verifier = MrSignerVerifier::new(
        signature.mrsigner().into(),
        signature.product_id(),
        override_minimum_svn.unwrap_or_else(|| signature.version()),
    );
    mr_signer_verifier.set_advisories(advisories);
    mr_signer_verifier
}

pub fn get_mr_enclave_verifier() -> MrEnclaveVerifier {
    let advisories: Advisories =
        Advisories::new(HARDENING_ADVISORIES, AdvisoryStatus::SWHardeningNeeded);
    let mut mr_enclave_verifier = MrEnclaveVerifier::from(sigstruct());
    mr_enclave_verifier.set_advisories(advisories);
    mr_enclave_verifier
}
