// Copyright (c) 2023 The MobileCoin Foundation

//! A simulated implementation of DCAP quote generation.

use crate::TargetInfoError;
use mc_attest_core::QuoteError;
use mc_attest_verifier::{IAS_SIM_SIGNING_CHAIN, IAS_SIM_SIGNING_KEY};
use mc_rand::McRng;
use mc_sgx_core_types::{Report, ReportBody, TargetInfo};
use mc_sgx_dcap_sys_types::{sgx_ql_ecdsa_sig_data_t, sgx_quote3_t, sgx_quote_header_t};
use mc_sgx_dcap_types::Quote3;
use mc_sgx_types::sgx_report_body_t;
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use std::{mem, str::FromStr};

pub struct SimQuotingEnclave;

impl SimQuotingEnclave {
    /// Get a quote based on the application enclave's `report`.
    pub fn quote_report(report: &Report) -> Result<Quote3<Vec<u8>>, QuoteError> {
        let cert_data = pck_cert_chain();

        let sgx_quote = sgx_quote(report.body(), &cert_data);
        let mut quote_bytes = c_struct_as_bytes(&sgx_quote).to_vec();

        let mut rng = McRng::default();
        let signing_key = SigningKey::random(&mut rng);
        let signature = (&signing_key as &dyn Signer<Signature>).sign(&quote_bytes);

        let ecdsa_sig = ecdsa_sig_data(signature, signing_key.verifying_key(), report.body());
        let ecdsa_bytes = c_struct_as_bytes(&ecdsa_sig);

        quote_bytes.extend(ecdsa_bytes);
        quote_bytes.extend(cert_data);

        let quote = Quote3::try_from(quote_bytes)?;
        Ok(quote)
    }

    /// Get the target info for the quoting enclave.
    pub fn target_info() -> Result<TargetInfo, TargetInfoError> {
        Ok(TargetInfo::default())
    }
}

fn sgx_quote(report_body: ReportBody, cert_data: &[u8]) -> sgx_quote3_t {
    let header = sgx_quote_header_t {
        version: 3,
        att_key_type: 2,
        att_key_data_0: 0,
        qe_svn: 0,
        pce_svn: 0,
        vendor_id: [0; 16],
        user_data: [0; 20],
    };

    sgx_quote3_t {
        header,
        report_body: report_body.into(),
        signature_data_len: mem::size_of::<sgx_ql_ecdsa_sig_data_t>() as u32
            + cert_data.len() as u32,
        signature_data: Default::default(),
    }
}

fn pck_cert_chain() -> Vec<u8> {
    // [ 2 bytes authentication data | 2 bytes certification data type ]
    let mut pck_cert_chain = vec![0x00, 0x00, 0x05, 0x00];

    let cert_chain = IAS_SIM_SIGNING_CHAIN.as_bytes();
    let size = cert_chain.len() as u32;
    pck_cert_chain.extend_from_slice(&size.to_le_bytes());
    pck_cert_chain.extend(cert_chain);
    pck_cert_chain
}

fn ecdsa_sig_data(
    signature: Signature,
    verifying_key: &VerifyingKey,
    qe_report_body: ReportBody,
) -> sgx_ql_ecdsa_sig_data_t {
    // Encoded points are 65 bytes long and start with 0x04 tag byte for the SEC 1
    // uncompressed format. We want to strip the tag byte off.
    let encoded_point = verifying_key.to_encoded_point(false);
    let verifying_key_bytes = &encoded_point.as_bytes()[1..];

    let pck_signing_key =
        SigningKey::from_str(IAS_SIM_SIGNING_KEY).expect("Failed to decode signing key");
    let qe_signature = (&pck_signing_key as &dyn Signer<Signature>).sign(c_struct_as_bytes(
        &sgx_report_body_t::from(qe_report_body.clone()),
    ));

    sgx_ql_ecdsa_sig_data_t {
        sig: signature.to_bytes().into(),
        attest_pub_key: verifying_key_bytes
            .try_into()
            .expect("Not enough bytes for verifying key"),
        qe_report: qe_report_body.into(),
        qe_report_sig: qe_signature.to_bytes().into(),
        auth_certification_data: Default::default(),
    }
}

#[allow(unsafe_code)]
// This should only be used for repr(C) structs.
fn c_struct_as_bytes<T>(quote: &T) -> &[u8] {
    // SAFETY: This is a private function only used in the sim configuration.
    // The normal C api will use direct memory access on the bytes coming
    // across the wire. The lifetime of the byte slice is tied to the lifetime of
    // the input reference.
    unsafe { core::slice::from_raw_parts(quote as *const T as *const u8, mem::size_of::<T>()) }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn simulated_quote_from_report() {
        let report = Report::default();
        let quote = SimQuotingEnclave::quote_report(&report).expect("Failed to get quote");
        assert_eq!(quote.app_report_body(), &report.body());
    }
}
