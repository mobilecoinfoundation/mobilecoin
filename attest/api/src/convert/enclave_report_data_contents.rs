// Copyright (c) 2023 The MobileCoin Foundation

//! Convert to/from attest::EnclaveReportDataContents

use crate::{attest, convert::encode_to_protobuf_vec, ConversionError};
use mc_attest_verifier_types::{prost, EnclaveReportDataContents};
use mc_util_serial::Message;
use protobuf::Message as ProtoMessage;

impl From<&EnclaveReportDataContents> for attest::EnclaveReportDataContents {
    fn from(src: &EnclaveReportDataContents) -> Self {
        let prost = prost::EnclaveReportDataContents::from(src);
        let bytes = prost.encode_to_vec();
        let mut proto = Self::default();
        proto
            .merge_from_bytes(&bytes)
            .expect("failure to merge means prost and protobuf are out of sync");
        proto
    }
}

impl TryFrom<&attest::EnclaveReportDataContents> for EnclaveReportDataContents {
    type Error = ConversionError;
    fn try_from(src: &attest::EnclaveReportDataContents) -> Result<Self, Self::Error> {
        let bytes = encode_to_protobuf_vec(src)?;
        let prost = prost::EnclaveReportDataContents::decode(bytes.as_slice())?;
        prost.try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_to_proto() {
        let report_data = EnclaveReportDataContents::new(
            [0x32u8; 16].into(),
            [0x77u8; 32].as_slice().try_into().expect("bad key"),
            [0xCCu8; 32],
        );

        let proto_report_data = attest::EnclaveReportDataContents::from(&report_data);
        let new_report_data =
            EnclaveReportDataContents::try_from(&proto_report_data).expect("failed to convert");

        assert_eq!(report_data, new_report_data);
    }

    #[test]
    fn roundtrip_to_proto_no_custom_id() {
        let report_data = EnclaveReportDataContents::new(
            [0x32u8; 16].into(),
            [0x77u8; 32].as_slice().try_into().expect("bad key"),
            None,
        );

        let proto_report_data = attest::EnclaveReportDataContents::from(&report_data);
        let new_report_data =
            EnclaveReportDataContents::try_from(&proto_report_data).expect("failed to convert");

        assert_eq!(report_data, new_report_data);
    }
}
