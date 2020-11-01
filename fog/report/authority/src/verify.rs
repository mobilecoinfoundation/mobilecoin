// Copyright (c) 2018-2020 MobileCoin Inc.

//! Verify fog authority and report signature.

use crate::{
    validated_chain::{CertValidationError, ValidatedChain},
    ProstReports,
};
use core::convert::TryFrom;
use displaydoc::Display;
use mc_account_keys::FOG_AUTHORITY_SIGNATURE_TAG;
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_keys::{
    Ed25519Public, Ed25519Signature, Ed25519SignatureError, RistrettoPublic, Signature, Verifier,
};
use mc_fog_api::report;
use prost::DecodeError;
use protobuf::{Message as ProtobufMessage, ProtobufError};
use schnorrkel::{Signature as SchnorrkelSignature, SignatureError as SchnorrkelSignatureError};

/// Enumeration of possible errors in course of verifying fog authority
#[derive(Debug, Display)]
pub enum ReportAuthorityError {
    /// Certificate is invalid {0}
    InvalidCertificate(CertValidationError),
    /// Verification failure
    VerificationFailure,
    /// Could not create Ed25519Public from cert pubkey
    Ed25519ParseError,
    /// Ed25519 Signature Error {0}
    SignatureError(Ed25519SignatureError),
    /// Cert signature validation failed
    CertSignatureFailure,
    /// Schnorrkel signature validation failed
    SchnorrkelSignatureFailure,
    /// Empty Cert Chain
    EmptyCertChain,
    /// Protobuf Error
    ProtobufError,
    /// Prost Decode Error
    ProstDecodeError,
}

impl From<CertValidationError> for ReportAuthorityError {
    fn from(src: CertValidationError) -> Self {
        Self::InvalidCertificate(src)
    }
}

impl From<mc_crypto_keys::KeyError> for ReportAuthorityError {
    fn from(_src: mc_crypto_keys::KeyError) -> Self {
        Self::Ed25519ParseError
    }
}

impl From<Ed25519SignatureError> for ReportAuthorityError {
    fn from(src: Ed25519SignatureError) -> Self {
        Self::SignatureError(src)
    }
}

impl From<SchnorrkelSignatureError> for ReportAuthorityError {
    fn from(_src: SchnorrkelSignatureError) -> Self {
        Self::SchnorrkelSignatureFailure
    }
}

impl From<ProtobufError> for ReportAuthorityError {
    fn from(_src: ProtobufError) -> Self {
        Self::ProtobufError
    }
}

impl From<DecodeError> for ReportAuthorityError {
    fn from(_src: DecodeError) -> Self {
        Self::ProstDecodeError
    }
}

/// Verify the signature over the reports.
fn verify_signature_over_reports(
    report_response: &report::ReportResponse,
    pubkey_bytes: &[u8],
) -> Result<(), ReportAuthorityError> {
    // For the final cert in the chain, check that the report signature verifies with the pubkey.
    let report_sig = Ed25519Signature::from_bytes(report_response.get_reports_sig())?;

    // Construct contents hash, expected to be under signature by the terminal Ed25519 key
    let reports = report_response.get_reports();
    let protobuf_bytes = reports.write_to_bytes()?;
    let prost_reports: ProstReports = mc_util_serial::decode(&protobuf_bytes)?;
    let contents_hash = prost_reports.digest32::<MerlinTranscript>(b"reports");
    /*let mut contents_hash = [0u8; 32];
    {
        let mut transcript = MerlinTranscript::new(b"reports");
        for report in report_response.get_reports() {
            let report_digest = report::digest32();
            // Construct ReportData
            let response_report = ReportData {
                report: report.get_report_data().get_report().to_vec(),
                pubkey_expiry: report.get_report_data().get_pubkey_expiry(),
            };
            response_report.append_to_transcript(b"report_data", &mut transcript);

            let report_id = report.get_fog_report_id();
            report_id.append_to_transcript(b"report_id", &mut transcript);
        }
        transcript.extract_digest(&mut contents_hash);
    }
     */

    // Get pubkey (Ed25519) from bytes
    let pubkey_from_cert: Ed25519Public = Ed25519Public::try_from(pubkey_bytes)?;

    // Verify the signature from the report contents
    pubkey_from_cert.verify(&contents_hash, &report_sig)?;
    Ok(())
}

/// Verify fog authority key against the recipient's signature.
fn verify_authority_signature(
    recipient_pubkey: &RistrettoPublic,
    recipient_fog_authority_sig: &SchnorrkelSignature,
    pubkey_bytes: &[u8],
) -> Result<(), ReportAuthorityError> {
    mc_crypto_sig::verify(
        FOG_AUTHORITY_SIGNATURE_TAG,
        recipient_pubkey,
        &pubkey_bytes,
        recipient_fog_authority_sig,
    )?;
    Ok(())
}

/// Verify the fog authority identifier in the report.
///
/// Verification requires a single-path certificate chain, where the root
/// contains the x509 extension for the AuthorityKeyId, which is the hash of the
/// SubjectPublicKeyInfo. The last cert in the chain must contain an Ed25519 Public Key
/// which verifies the signature of the Report (report_sig). Any other certificate
/// chain construction is invalid.
///
/// Cert chain verification proceeds as follows:
/// * Verify root is valid and contains expected AuthorityKeyId
/// * Verify next cert was issued by previous cert, and we have not exceeded MaxLength
/// * So on, until the end of the chain, where we verify the signature.
pub fn verify_fog_authority(
    report_response: &report::ReportResponse,
    recipient_pubkey: &RistrettoPublic,
    recipient_fog_authority_sig: &SchnorrkelSignature,
) -> Result<(), ReportAuthorityError> {
    // Check that the root cert is valid and contains the expected Authority Public Key
    let validated_chain =
        ValidatedChain::from_chain_bytes(&report_response.get_cert_chain().to_vec())?;
    verify_authority_signature(
        recipient_pubkey,
        recipient_fog_authority_sig,
        &validated_chain.root_public_key(),
    )?;

    verify_signature_over_reports(&report_response, &validated_chain.terminal_public_key())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::validated_chain::{parse_keypair_from_pem, split_certs_to_byte_vec};
    use mc_account_keys::{AccountKey, RootIdentity};
    use mc_crypto_keys::{DistinguishedEncoding, Ed25519Pair, Signer};
    use protobuf::RepeatedField;
    use rand_core::{CryptoRng, RngCore, SeedableRng};
    use rand_hc::Hc128Rng as FixedRng;
    use std::{string::ToString, vec};
    use x509_parser::{parse_x509_der, pem::pem_to_der};

    fn test_fog_account_key<T: RngCore + CryptoRng>(rng: &mut T) -> AccountKey {
        // The Authority Public Key present in the test certificate
        // HACK to verify RT until we decide what pubkey fingerprint goes under the signature
        let fog_authority_cert_chain = include_str!("../tests/data/chain.pem");
        let certs = split_certs_to_byte_vec(fog_authority_cert_chain);
        let root = certs[0].clone();
        let cert_pem = pem_to_der(&root).unwrap().1.contents;
        let authority_key_bytes = parse_x509_der(&cert_pem)
            .unwrap()
            .1
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;

        // Construct Schnorrkel signature over the authority key fingerprint via
        // creating an account key
        let root_id = RootIdentity::random_with_fog(
            rng,
            "fog://discovery.alpha.mobilecoin.com",
            "",
            &authority_key_bytes,
        );
        AccountKey::from(&root_id)
    }

    #[test]
    fn test_signature_verification() {
        let mut rng: FixedRng = SeedableRng::from_seed([42u8; 32]);

        // Load cert chain
        let fog_authority_cert_chain = include_str!("../tests/data/test2/chain.pem");
        let certs = split_certs_to_byte_vec(fog_authority_cert_chain);
        let validated_chain = ValidatedChain::from_chain_bytes(&certs).unwrap();

        // Extract Report Server's signing key from test cert
        let signing_key_str = include_str!("../tests/data/test2/server-ed25519.key");
        let signing_key: Ed25519Pair =
            parse_keypair_from_pem(&signing_key_str).expect("Could not parse keypair");

        // Sanity check
        let ed25519_cert = include_str!("../tests/data/test2/server-ed25519.crt");
        let cert_pem = pem_to_der(&ed25519_cert.as_bytes().to_vec())
            .unwrap()
            .1
            .contents;
        assert_eq!(
            signing_key.public_key().to_der(),
            parse_x509_der(&cert_pem)
                .unwrap()
                .1
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .data
        );

        // Sanity check that terminal pubkey matches signer pubkey
        let terminal = certs[certs.len() - 1].clone();
        let cert_pem = pem_to_der(&terminal).unwrap().1.contents;
        assert_eq!(
            signing_key.public_key().to_der(),
            parse_x509_der(&cert_pem)
                .unwrap()
                .1
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .data
        );

        // Construct the Report which Ingest would Publish to the ReportServer
        let report_id = "".to_string();
        let mut report = report::Report::new();
        report.set_fog_report_id(report_id);
        report.set_report(vec![0u8; 32]); // Contents (IAS response) not verified by verify_fog_authority
        report.set_pubkey_expiry(rng.next_u64()); // Contents not verified by verify_fog_authority

        let mut reports = report::Reports::new();
        reports.set_reports(RepeatedField::from_vec(vec![report]));

        // Construct the signature over the reports
        let protobuf_bytes = reports.write_to_bytes().unwrap();
        let prost_reports: ProstReports = mc_util_serial::decode(&protobuf_bytes).unwrap();
        let contents_hash = prost_reports.digest32::<MerlinTranscript>(b"reports");
        // let mut contents_hash = [0u8; 32];
        // {
        //     let mut transcript = MerlinTranscript::new(b"report-data");
        //     for report in reports.iter() {
        //         // Make the ReportData which is digestible
        //         let digestible_report_data = ReportData {
        //             report: report.get_report_data().get_report().to_vec().clone(),
        //             pubkey_expiry: report.get_report_data().get_pubkey_expiry(),
        //         };
        //         digestible_report_data.append_to_transcript(b"report_data", &mut transcript);
        //         report
        //             .get_fog_report_id()
        //             .append_to_transcript(b"report_id", &mut transcript);
        //     }
        //     transcript.extract_digest(&mut contents_hash);
        // }
        println!(
            "\x1b[1;32m COnstructing sig with pubkey {:?}\x1b[0m",
            signing_key.public_key().to_der()
        );
        // Construct the ReportServer's signature over the array of Reports
        let report_sig = signing_key
            .try_sign(&contents_hash)
            .expect("Could not sign");

        let mut report_response = report::ReportResponse::new();
        report_response.set_reports(reports);
        report_response.set_reports_sig(report_sig.as_bytes().to_vec());
        report_response.set_cert_chain(RepeatedField::from_vec(certs.to_vec()));

        // First certificate pubkey should fail verification
        assert!(verify_signature_over_reports(
            &report_response,
            &validated_chain.root_public_key(),
        )
        .is_err());

        // Second certificate pubkey should pass verification
        assert!(verify_signature_over_reports(
            &report_response,
            &validated_chain.terminal_public_key(),
        )
        .is_ok());
    }

    #[test]
    fn test_authority_key_verification() {
        let mut rng: FixedRng = SeedableRng::from_seed([42u8; 32]);
        let account_key = test_fog_account_key(&mut rng);
        let subaddress = account_key.subaddress(rng.next_u64());

        // Load cert chain
        let fog_authority_cert_chain = include_str!("../tests/data/chain.pem");
        let certs = split_certs_to_byte_vec(fog_authority_cert_chain);
        let validated_chain = ValidatedChain::from_chain_bytes(&certs).unwrap();

        assert!(verify_authority_signature(
            &subaddress.view_public_key(),
            &SchnorrkelSignature::from_bytes(subaddress.fog_authority_fingerprint_sig().unwrap())
                .unwrap(),
            &mut validated_chain.root_public_key(),
        )
        .is_ok());

        // Second cert should fail, as it is not a ca, even though it has the authority key ID
        assert!(verify_authority_signature(
            &subaddress.view_public_key(),
            &SchnorrkelSignature::from_bytes(subaddress.fog_authority_fingerprint_sig().unwrap())
                .unwrap(),
            &mut validated_chain.terminal_public_key(),
        )
        .is_err());
    }

    #[test]
    fn test_verify_fog_authority() {
        let mut rng: FixedRng = SeedableRng::from_seed([42u8; 32]);
        let account_key = test_fog_account_key(&mut rng);
        let subaddress = account_key.subaddress(0);

        // Construct the Report which Ingest would Publish to the ReportServer
        let report_id = "".to_string();
        let mut report = report::Report::new();
        report.set_fog_report_id(report_id);
        report.set_report(vec![0u8; 32]); // Contents (IAS response) not verified by verify_fog_authority
        report.set_pubkey_expiry(rng.next_u64()); // Contents not verified by verify_fog_authority

        let mut reports = report::Reports::new();
        reports.set_reports(RepeatedField::from_vec(vec![report.clone()]));

        // Extract Report Server's signing key from test cert
        let signing_key_str = include_str!("../tests/data/server-ed25519.key");
        let signing_key: Ed25519Pair =
            parse_keypair_from_pem(&signing_key_str).expect("Could not parse keypair");

        // Sign all of the reports returned by this server (in this case only one)
        let protobuf_bytes = reports.write_to_bytes().unwrap();
        let prost_reports: ProstReports = mc_util_serial::decode(&protobuf_bytes).unwrap();
        let contents_hash = prost_reports.digest32::<MerlinTranscript>(b"reports");
        // let mut contents_hash = [0u8; 32];
        // {
        //     let mut transcript = MerlinTranscript::new(b"report-data");
        //     report_data.append_to_transcript(b"report_data", &mut transcript);
        //     report_id.append_to_transcript(b"report_id", &mut transcript);
        //     transcript.extract_digest(&mut contents_hash);
        // }
        // Construct the ReportServer's signature over the Reports
        let report_sig = signing_key
            .try_sign(&contents_hash)
            .expect("Could not sign");

        // Load cert chain
        let fog_authority_cert_chain = include_str!("../tests/data/chain.pem");
        let certs = split_certs_to_byte_vec(fog_authority_cert_chain);

        // Construct report response
        let mut reports_msg = report::Reports::new();
        reports_msg.set_reports(RepeatedField::from_vec(vec![report]));
        let mut report_response = report::ReportResponse::new();
        report_response.set_reports(reports_msg);
        report_response.set_reports_sig(report_sig.to_bytes().to_vec());
        report_response.set_cert_chain(RepeatedField::from_vec(certs));

        verify_fog_authority(
            &report_response,
            &subaddress.view_public_key(),
            &SchnorrkelSignature::from_bytes(subaddress.fog_authority_fingerprint_sig().unwrap())
                .unwrap(),
        )
        .expect("Could not verify fog authority");
    }
}
