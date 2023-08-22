// Copyright (c) 2023 The MobileCoin Foundation

//! A simulated implementation of DCAP quote generation.

use crate::TargetInfoError;
use mc_attest_core::QuoteError;
use mc_attest_verifier::{
    IAS_SIM_SIGNING_CHAIN, IAS_SIM_SIGNING_KEY, SIM_CRL, SIM_QE_IDENTITY, SIM_TCB_INFO
};
use mc_attestation_verifier::{QeIdentity, SignedQeIdentity};
use mc_rand::McRng;
use mc_sgx_core_types::{Report, ReportBody, TargetInfo};
use mc_sgx_dcap_sys_types::{
    sgx_ql_ecdsa_sig_data_t, sgx_ql_qve_collateral_t, sgx_quote3_t, sgx_quote_header_t,
};
use mc_sgx_dcap_types::{Collateral, Quote3};
use mc_sgx_types::sgx_report_body_t;
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
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
        // Per <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf#%5B%7B%22num%22%3A75%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C687%2C0%5D>
        // the signature is only over the header and report body of the quote.
        let signing_size =
            mem::size_of::<sgx_quote_header_t>() + mem::size_of::<sgx_report_body_t>();
        let signature = (&signing_key as &dyn Signer<Signature>).sign(&quote_bytes[..signing_size]);

        let ecdsa_sig = ecdsa_sig_data(signature, signing_key.verifying_key());
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

    pub fn collateral<Q: AsRef<[u8]>>(_quote: &Quote3<Q>) -> Collateral {
        let mut tcb_info = SIM_TCB_INFO.to_owned();
        let mut qe_identity = SIM_QE_IDENTITY.to_owned();

        let mut crl = SIM_CRL.to_vec();
        crl.push(0);

        // Normally the PCK chain would not be the same one used on TCB info and the QE
        // identity, but they share the same root so it works for this sim
        // implementation.
        let mut pem_chain = IAS_SIM_SIGNING_CHAIN.as_bytes().to_vec();

        let mut sgx_collateral = version_3_1_empty_collateral();
        sgx_collateral.root_ca_crl = crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.root_ca_crl_size = crl.len() as u32;
        sgx_collateral.pck_crl_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.pck_crl = crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_size = crl.len() as u32;
        sgx_collateral.tcb_info_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.tcb_info = tcb_info.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_size = tcb_info.len() as u32;
        sgx_collateral.qe_identity_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.qe_identity = qe_identity.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_size = qe_identity.len() as u32;

        Collateral::try_from(&sgx_collateral).expect("Failed to convert collateral")
    }
}

fn version_3_1_empty_collateral() -> sgx_ql_qve_collateral_t {
    let mut collateral = sgx_ql_qve_collateral_t::default();
    // Version 3.1 is the common default.
    //
    // The versions are documented in the default PCCS config file,
    // <https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/e7604e02331b3377f3766ed3653250e03af72d45/QuoteGeneration/qcnl/linux/sgx_default_qcnl.conf#L15>
    let (major, minor) = (3, 1);

    // SAFETY: The version fields are a union, which is inherently unsafe.
    // This is a sim only function that sets the major and minor flavor of
    // the union fields.
    #[allow(unsafe_code)]
    unsafe {
        collateral
            .__bindgen_anon_1
            .__bindgen_anon_1
            .as_mut()
            .major_version = major;
        collateral
            .__bindgen_anon_1
            .__bindgen_anon_1
            .as_mut()
            .minor_version = minor;
    }
    collateral
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

fn ecdsa_sig_data(signature: Signature, verifying_key: &VerifyingKey) -> sgx_ql_ecdsa_sig_data_t {
    // Encoded points are 65 bytes long and start with 0x04 tag byte for the SEC 1
    // uncompressed format. The `attest_pub_key` member of `sgx_ql_ecdsa_sig_data_t`
    // contains the uncompressed key as `X` component followed by `Y` component.
    // We need to strip the tag byte off since it is not part of the
    // `attest_pub_key`.
    let encoded_point = verifying_key.to_encoded_point(false);
    let verifying_key_bytes = &encoded_point.as_bytes()[1..];

    let hash = Sha256::digest(verifying_key_bytes);
    let mut qe_report_body = qe_report_body();
    qe_report_body.as_mut().report_data.d[..hash.len()].copy_from_slice(hash.as_slice());
    let pck_signing_key =
        SigningKey::from_str(IAS_SIM_SIGNING_KEY).expect("Failed to decode signing key");
    let qe_signature = (&pck_signing_key as &dyn Signer<Signature>)
        .sign(c_struct_as_bytes(qe_report_body.as_ref()));

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

fn qe_report_body() -> ReportBody {
    let identity_json = SIM_QE_IDENTITY;
    let signed_qe_identity =
        SignedQeIdentity::try_from(identity_json).expect("Failed to parse signed QE identity");
    let qe_identity =
        QeIdentity::try_from(&signed_qe_identity).expect("Failed to parse QE identity");
    let mut report_body = ReportBody::default();
    let sgx_report_body = report_body.as_mut();
    sgx_report_body.mr_signer = *qe_identity.mr_signer().as_ref();
    sgx_report_body.isv_prod_id = *qe_identity.isv_prod_id().as_ref();
    sgx_report_body.misc_select = *qe_identity.miscellaneous_select().as_ref();
    sgx_report_body.attributes = *qe_identity.attributes().as_ref();
    let isv_svn = qe_identity
        .tcb_levels()
        .first()
        .expect("No TCB levels in QE identity")
        .isv_svn();
    sgx_report_body.isv_svn = *isv_svn.as_ref();

    report_body
}

#[allow(unsafe_code)]
// This should only be used for repr(C) structs.
fn c_struct_as_bytes<T>(c_struct: &T) -> &[u8] {
    // SAFETY: This is a private function only used in the sim configuration.
    // The normal C api will use direct memory access on the bytes coming
    // across the wire. The lifetime of the byte slice is tied to the lifetime of
    // the input reference.
    unsafe { core::slice::from_raw_parts(c_struct as *const T as *const u8, mem::size_of::<T>()) }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_attest_core::DcapEvidence;
    use mc_attest_verifier::DcapVerifier;
    use mc_attestation_verifier::{Evidence, TrustedMrEnclaveIdentity};
    use mc_sgx_dcap_types::{CertificationData, TcbInfo};
    use p256::pkcs8::der::DateTime;
    use prost::Message;
    use std::time::{SystemTime, UNIX_EPOCH};
    use x509_cert::{der::DecodePem, Certificate};

    #[test]
    fn simulated_quote_from_report() {
        let report = Report::default();
        let quote = SimQuotingEnclave::quote_report(&report).expect("Failed to get quote");
        assert_eq!(quote.app_report_body(), &report.body());
    }

    #[test]
    fn tcb_values_from_simulated_quote() {
        let report = Report::default();
        let quote = SimQuotingEnclave::quote_report(&report).expect("Failed to get quote");
        let signature_data = quote.signature_data();
        let certification_data = signature_data.certification_data();
        let CertificationData::PckCertificateChain(pem_chain) = certification_data else {
            panic!("Should have had PckCertificateChain in quote");
        };
        let leaf_pem = pem_chain
            .into_iter()
            .next()
            .expect("No certs in the quote data");
        let leaf_cert = Certificate::from_pem(leaf_pem).expect("Failed to parse leaf cert");
        let result = TcbInfo::try_from(&leaf_cert);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_simulated_quote() {
        let report = Report::default();
        let quote = SimQuotingEnclave::quote_report(&report).expect("Failed to get quote");
        let collateral = SimQuotingEnclave::collateral(&quote);
        let mr_enclave = quote.app_report_body().mr_enclave();
        let identities =
            &[TrustedMrEnclaveIdentity::new(mr_enclave, [] as [&str; 0], [] as [&str; 0]).into()];
        let evidence = Evidence::new(quote, collateral).expect("Failed to get evidence");

        // The certs, TCB info, and QE identity are generated at build time, so `now()`
        // should be alright to use in testing.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to get duration since epoch");
        let time =
            DateTime::from_unix_duration(now).expect("Failed to convert duration to DateTime");
        let verifier = DcapVerifier::new(identities, time);
        let verification = verifier.verify(evidence);
        assert_eq!(verification.is_success().unwrap_u8(), 1);
    }

    #[test]
    fn test_dcap_evidence_serialization() {
        let mut buf: Vec<u8> = vec![];
        let uut: DcapEvidence = Default::default();
        uut.encode(&mut buf)
            .expect("Failed to encode empty DcapEvidence");
        let decoded = DcapEvidence::decode(buf.as_slice())
            .expect("Failed to decode empty DcapEvidence");
        assert_eq!(uut, decoded);
        buf.clear();
        let report = Report::default();
        let quote = SimQuotingEnclave::quote_report(&report).expect("Failed to create quote");
        let collateral = SimQuotingEnclave::collateral(&quote);
        let uut = DcapEvidence { quote: Some(quote), collateral: Some(collateral) };
        uut.encode(&mut buf)
            .expect("Failed to encode DcapEvidence");
        let decoded = DcapEvidence::decode(buf.as_slice())
            .expect("Failed to decode DcapEvidence");
        assert_eq!(uut, decoded);
    }
}
