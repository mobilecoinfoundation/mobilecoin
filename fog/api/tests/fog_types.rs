use mc_attest_core::VerificationReport as ProstVerificationReport;
use mc_fog_api::{
    external::VerificationReport as ProtobufVerificationReport,
    report::{Report as ProtobufReport, ReportResponse as ProtobufReportResponse},
};
use mc_fog_types::{Report as ProstReport, ReportResponse as ProstReportResponse};
use prost::Message as ProstMessage;
use protobuf::Message as ProtobufMessage;

// Round trip a structure through protobuf type, once using serialization to bytes
// and deserialization, and once using the From conversions.
fn round_trip_prosty<SRC, DEST>(prost_val: SRC)
where
    SRC: ProstMessage + Eq + Default + Clone + From<DEST>,
    DEST: ProtobufMessage + From<SRC>,
{
    mc_fog_api_test_utils::round_trip_message::<SRC, DEST>(&prost_val);

    let prost_val2 = SRC::from(DEST::from(prost_val.clone()));
    assert!(prost_val == prost_val2);
}

// Round trip a structure through protobuf type, once using serialization to bytes
// and deserialization, and once using the From conversions.
fn round_trip_protobuf<SRC, DEST>(protobuf_val: SRC)
where
    SRC: ProtobufMessage + Eq + Clone + From<DEST>,
    DEST: ProstMessage + Default + From<SRC>,
{
    mc_fog_api_test_utils::round_trip_protobuf_object::<SRC, DEST>(&protobuf_val);

    let protobuf_val2 = SRC::from(DEST::from(protobuf_val.clone()));
    assert!(protobuf_val == protobuf_val2);
}

fn prost_report(name: &str) -> ProstVerificationReport {
    ProstVerificationReport {
        sig: format!("{} sig", name).as_bytes().to_vec().into(),
        chain: Default::default(),
        http_body: format!("{} body", name),
    }
}

// Make some prost test cases
fn prost_test_cases() -> Vec<ProstReport> {
    vec![
        ProstReport {
            fog_report_id: Default::default(),
            report: prost_report("foobar"),
            pubkey_expiry: 1000,
        },
        ProstReport {
            fog_report_id: "eap".to_string(),
            report: prost_report("baz"),
            pubkey_expiry: 10000,
        },
        ProstReport {
            fog_report_id: "".to_string(),
            report: prost_report("quz"),
            pubkey_expiry: 0,
        },
    ]
}

fn protobuf_report(name: &str) -> ProtobufVerificationReport {
    let mut report = ProtobufVerificationReport::new();
    report.set_sig(format!("{} sig", name).as_bytes().to_vec());
    report.set_http_body(format!("{} body", name));
    report
}

// Make some prost test cases
fn protobuf_test_cases() -> Vec<ProtobufReport> {
    let mut rep1 = ProtobufReport::new();
    rep1.set_report(protobuf_report("asdf"));
    rep1.set_pubkey_expiry(199);

    let mut rep2 = ProtobufReport::new();
    rep2.set_fog_report_id("non".to_string());
    rep2.set_report(protobuf_report("jkl"));
    rep2.set_pubkey_expiry(11);

    let mut rep3 = ProtobufReport::new();
    rep3.set_report(protobuf_report(";;;"));
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
        round_trip_protobuf::<ProtobufReport, ProstReport>(case);
    }
}

#[test]
fn round_trip_prost_report_response() {
    round_trip_prosty::<ProstReportResponse, ProtobufReportResponse>(ProstReportResponse {
        reports: prost_test_cases(),
        chain: make_chain(),
        signature: b"report sig".to_vec(),
    });
}

#[test]
fn round_trip_protobuf_report_response() {
    let mut case = ProtobufReportResponse::new();
    case.set_reports(protobuf::RepeatedField::from_vec(protobuf_test_cases()));
    case.set_chain(make_chain().into());
    case.set_signature(b"report sig".to_vec());
    round_trip_protobuf::<ProtobufReportResponse, ProstReportResponse>(case);
}
