// Copyright (c) 2018-2021 The MobileCoin Foundation

#![feature(external_doc)]
#![doc(include = "../README.md")]
#![no_std]

use core::convert::TryFrom;
use mc_attest_core::{MrEnclaveVerifier, MrSignerVerifier, SecurityVersion};
use mc_sgx_css::Signature;

pub fn sigstruct() -> Signature {
    Signature::try_from(&include_bytes!(env!("MCBUILD_ENCLAVE_CSS_PATH"))[..])
        .expect("Could not read ingest enclave metadata")
}

pub const CONFIG_ADVISORIES: &[&str] = &[];
pub const HARDENING_ADVISORIES: &[&str] = &["INTEL-SA-00334"];

pub fn get_mr_signer_verifier(override_minimum_svn: Option<SecurityVersion>) -> MrSignerVerifier {
    let signature = sigstruct();
    let mut mr_signer_verifier = MrSignerVerifier::new(
        signature.mrsigner().into(),
        signature.product_id(),
        override_minimum_svn.unwrap_or_else(|| signature.version()),
    );
    mr_signer_verifier.allow_config_advisories(CONFIG_ADVISORIES);
    mr_signer_verifier.allow_hardening_advisories(HARDENING_ADVISORIES);
    mr_signer_verifier
}

pub fn get_mr_enclave_verifier() -> MrEnclaveVerifier {
    let mut mr_enclave_verifier = MrEnclaveVerifier::from(sigstruct());
    mr_enclave_verifier.allow_config_advisories(CONFIG_ADVISORIES);
    mr_enclave_verifier.allow_hardening_advisories(HARDENING_ADVISORIES);
    mr_enclave_verifier
}
