// Copyright (c) 2018-2022 The MobileCoin Foundation

use ::prost::Message as ProstMessage;
use mc_attest_verifier_types::prost;
use mc_fog_report_api::{
    external::{
        DcapEvidence as ProtobufDcapEvidence,
        EnclaveReportDataContents as ProtobufEnclaveReportDataContents,
    },
    fog_report::{report, Report as ProtobufReport, ReportResponse as ProtobufReportResponse},
};
use mc_fog_report_api_test_utils::round_trip_message;
use mc_fog_report_types::{
    AttestationEvidence as ProstAttestationEvidence, Report as ProstReport,
    ReportResponse as ProstReportResponse,
};

// Round trip a structure through protobuf type, once using serialization to
// bytes and deserialization, and once using the From conversions.
fn round_trip_prosty<SRC, DEST>(prost_val: SRC)
where
    SRC: ProstMessage + Eq + Default + Clone + From<DEST>,
    DEST: ProstMessage + Default + From<SRC>,
{
    round_trip_message::<SRC, DEST>(&prost_val);

    let prost_val2 = SRC::from(DEST::from(prost_val.clone()));
    assert!(prost_val == prost_val2);
}

// Round trip a structure through protobuf type, once using serialization to
// bytes and deserialization, and once using the From conversions.
fn round_trip_protobuf<SRC, DEST>(protobuf_val: SRC)
where
    SRC: ProstMessage + Default + Eq + Clone + From<DEST>,
    DEST: ProstMessage + Default + From<SRC>,
{
    round_trip_message::<SRC, DEST>(&protobuf_val);

    let protobuf_val2 = SRC::from(DEST::from(protobuf_val.clone()));
    assert!(protobuf_val == protobuf_val2);
}

fn prost_attestation_evidence(name: &str) -> ProstAttestationEvidence {
    // Note the prost::DcapEvidence to external::DcapEvidence is thoroughly tested
    // in `mc-api`. These tests are to ensure the `AttestationEvidence` conversion
    // is correct. So for ease of testing we set up the
    // EnclaveReportDataContents as it's the easiest to initialize to dummy
    // values.
    let report_data = prost::EnclaveReportDataContents {
        nonce: format!("{name} prost nonce").into_bytes(),
        key: format!("{name} prost key").into_bytes(),
        custom_identity: format!("{name} prost custom_identity").into_bytes(),
    };
    prost::DcapEvidence {
        quote: None,
        collateral: None,
        report_data: Some(report_data),
    }
    .into()
}

// Make some prost test cases
fn prost_test_cases() -> Vec<ProstReport> {
    vec![
        ProstReport {
            fog_report_id: Default::default(),
            attestation_evidence: Some(prost_attestation_evidence("foobar")),
            pubkey_expiry: 1000,
        },
        ProstReport {
            fog_report_id: "eap".to_string(),
            attestation_evidence: Some(prost_attestation_evidence("baz")),
            pubkey_expiry: 10000,
        },
        ProstReport {
            fog_report_id: "".to_string(),
            attestation_evidence: Some(prost_attestation_evidence("quz")),
            pubkey_expiry: 0,
        },
    ]
}

fn protobuf_dcap_evidence(name: &str) -> ProtobufDcapEvidence {
    let report_data = ProtobufEnclaveReportDataContents {
        nonce: format!("{name} protobuf nonce").into_bytes(),
        key: format!("{name} protobuf key").into_bytes(),
        custom_identity: format!("{name} protobuf custom_identity").into_bytes(),
    };

    ProtobufDcapEvidence {
        report_data: Some(report_data),
        ..Default::default()
    }
}

// Make some prost test cases
fn protobuf_test_cases() -> Vec<ProtobufReport> {
    let rep1 = ProtobufReport {
        attestation_evidence: Some(report::AttestationEvidence::DcapEvidence(
            protobuf_dcap_evidence("foo"),
        )),
        pubkey_expiry: 199,
        ..Default::default()
    };

    let rep2 = ProtobufReport {
        attestation_evidence: Some(report::AttestationEvidence::DcapEvidence(
            protobuf_dcap_evidence("non"),
        )),
        pubkey_expiry: 11,
        ..Default::default()
    };

    let rep3 = ProtobufReport {
        attestation_evidence: Some(report::AttestationEvidence::DcapEvidence(
            protobuf_dcap_evidence(";;;"),
        )),
        ..Default::default()
    };
    vec![rep1, rep2, rep3]
}

fn make_chain() -> Vec<Vec<u8>> {
    vec![b"abc".to_vec(), b"easy as".to_vec(), b"123".to_vec()]
}

#[test]
fn round_trip_prost_report() {
    for case in prost_test_cases() {
        round_trip_prosty::<ProstReport, ProtobufReport>(case);
    }
}

#[test]
fn round_trip_protobuf_report() {
    for case in protobuf_test_cases() {
        eprintln!("report = {case:?}");
        round_trip_protobuf::<ProtobufReport, ProstReport>(case);
    }
}

#[test]
fn round_trip_prost_report_response() {
    round_trip_prosty::<ProstReportResponse, ProtobufReportResponse>(ProstReportResponse {
        reports: prost_test_cases(),
        chain: make_chain(),
        signature: b"report signature".to_vec(),
    });
}

#[test]
fn round_trip_protobuf_report_response() {
    let case = ProtobufReportResponse {
        reports: protobuf_test_cases(),
        chain: make_chain(),
        signature: b"report signature".to_vec(),
    };
    round_trip_protobuf::<ProtobufReportResponse, ProstReportResponse>(case);
}
