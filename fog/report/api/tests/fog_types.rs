// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_attest_verifier_types::prost;
use mc_fog_report_api::{
    external::{
        DcapEvidence as ProtobufDcapEvidence,
        Collateral as ProtobufCollateral,
        EnclaveReportDataContents as ProtobufEnclaveReportDataContents,
        Quote3 as ProtobufQuote3,
    },
    report::{Report as ProtobufReport, ReportResponse as ProtobufReportResponse},
};
use mc_fog_report_api_test_utils::{round_trip_message, round_trip_protobuf_object};
use mc_fog_report_types::{Report as ProstReport, ReportResponse as ProstReportResponse};
use ::prost::Message as ProstMessage;
use protobuf::{Message as ProtobufMessage, RepeatedField};

// Round trip a structure through protobuf type, once using serialization to
// bytes and deserialization, and once using the From conversions.
fn round_trip_prosty<SRC, DEST>(prost_val: SRC)
where
    SRC: ProstMessage + Eq + Default + Clone + From<DEST>,
    DEST: ProtobufMessage + From<SRC>,
{
    round_trip_message::<SRC, DEST>(&prost_val);

    let prost_val2 = SRC::from(DEST::from(prost_val.clone()));
    assert!(prost_val == prost_val2);
}

// Round trip a structure through protobuf type, once using serialization to
// bytes and deserialization, and once using the From conversions.
fn round_trip_protobuf<SRC, DEST>(protobuf_val: SRC)
where
    SRC: ProtobufMessage + Eq + Clone + From<DEST>,
    DEST: ProstMessage + Default + From<SRC>,
{
    round_trip_protobuf_object::<SRC, DEST>(&protobuf_val);

    let protobuf_val2 = SRC::from(DEST::from(protobuf_val.clone()));
    assert!(protobuf_val == protobuf_val2);
}

fn prost_attestation_evidence(name: &str) -> prost::DcapEvidence {
    let quote = prost::Quote3{
        data: format!("{name} quote").into_bytes().into(),
    };
    let report_data = prost::EnclaveReportDataContents{
        nonce: format!("{name} nonce").into_bytes().into(),
        key: format!("{name} key").into_bytes().into(),
        custom_identity: format!("{name} custom_id").into_bytes().into(),
    };
    prost::DcapEvidence {
        quote: Some(quote),
        collateral: Some(Default::default()),
        report_data: Some(report_data),
    }
}

// Make some prost test cases
fn prost_test_cases() -> Vec<ProstReport> {
    vec![
        ProstReport {
            fog_report_id: Default::default(),
            attestation_evidence: prost_attestation_evidence("foobar"),
            pubkey_expiry: 1000,
        },
        ProstReport {
            fog_report_id: "eap".to_string(),
            attestation_evidence: prost_attestation_evidence("baz"),
            pubkey_expiry: 10000,
        },
        ProstReport {
            fog_report_id: "".to_string(),
            attestation_evidence: prost_attestation_evidence("quz"),
            pubkey_expiry: 0,
        },
    ]
}

fn protobuf_attestation_evidence(name: &str) -> ProtobufDcapEvidence {
    let mut quote = ProtobufQuote3::new();
    quote.set_data(format!("{name} quote").into_bytes());

    let mut report_data = ProtobufEnclaveReportDataContents::new();
    report_data.set_nonce(format!("{name} nonce").into_bytes());
    report_data.set_key(format!("{name} key").into_bytes());
    report_data.set_custom_identity(format!("{name} custom_id").into_bytes());


    let mut evidence = ProtobufDcapEvidence::new();
    evidence.set_quote(quote);
    evidence.set_collateral(ProtobufCollateral::new());
    evidence.set_report_data(report_data);

    evidence
}

// Make some prost test cases
fn protobuf_test_cases() -> Vec<ProtobufReport> {
    let mut rep1 = ProtobufReport::new();
    rep1.set_attestation_evidence(protobuf_attestation_evidence("asdf"));
    rep1.set_pubkey_expiry(199);

    let mut rep2 = ProtobufReport::new();
    rep2.set_fog_report_id("non".to_string());
    rep2.set_attestation_evidence(protobuf_attestation_evidence("jkl"));
    rep2.set_pubkey_expiry(11);

    let mut rep3 = ProtobufReport::new();
    rep3.set_attestation_evidence(protobuf_attestation_evidence(";;;"));
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
    let mut case = ProtobufReportResponse::new();
    case.set_reports(RepeatedField::from_vec(protobuf_test_cases()));
    case.set_chain(make_chain().into());
    case.set_signature(b"report signature".to_vec());
    round_trip_protobuf::<ProtobufReportResponse, ProstReportResponse>(case);
}
