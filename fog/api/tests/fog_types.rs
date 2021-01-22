use mc_fog_api::report::{Report as ProtobufReport, ReportResponse as ProtobufReportResponse};
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

// Make some prost test cases
fn prost_test_cases() -> Vec<ProstReport> {
    vec![
        ProstReport {
            fog_report_id: Default::default(),
            report: b"foobar".to_vec(),
            pubkey_expiry: 1000,
        },
        ProstReport {
            fog_report_id: "eap".to_string(),
            report: b"baz".to_vec(),
            pubkey_expiry: 10000,
        },
        ProstReport {
            fog_report_id: "".to_string(),
            report: b"quz".to_vec(),
            pubkey_expiry: 0,
        },
    ]
}

// Make some prost test cases
fn protobuf_test_cases() -> Vec<ProtobufReport> {
    let mut rep1 = ProtobufReport::new();
    rep1.set_report(b"asdf".to_vec());
    rep1.set_pubkey_expiry(199);

    let mut rep2 = ProtobufReport::new();
    rep2.set_fog_report_id("non".to_string());
    rep2.set_report(b"jkl".to_vec());
    rep2.set_pubkey_expiry(11);

    let mut rep3 = ProtobufReport::new();
    rep3.set_report(b";;;".to_vec());
    vec![rep1, rep2, rep3]
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
    });
}

#[test]
fn round_trip_protobuf_report_response() {
    let mut case = ProtobufReportResponse::new();
    case.set_reports(protobuf::RepeatedField::from_vec(protobuf_test_cases()));
    round_trip_protobuf::<ProtobufReportResponse, ProstReportResponse>(case);
}
