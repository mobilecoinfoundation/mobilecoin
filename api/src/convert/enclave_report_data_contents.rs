// Copyright (c) 2023 The MobileCoin Foundation

//! Convert to/from external::EnclaveReportDataContents

use crate::{convert::encode_to_protobuf_vec, external, ConversionError};
use mc_attest_verifier_types::{prost, EnclaveReportDataContents};
use mc_util_serial::Message;
use protobuf::Message as ProtoMessage;

impl From<&EnclaveReportDataContents> for external::EnclaveReportDataContents {
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

impl TryFrom<&external::EnclaveReportDataContents> for EnclaveReportDataContents {
    type Error = ConversionError;
    fn try_from(src: &external::EnclaveReportDataContents) -> Result<Self, Self::Error> {
        let bytes = encode_to_protobuf_vec(src)?;
        let prost = prost::EnclaveReportDataContents::decode(bytes.as_slice())?;
        Ok(prost.try_into()?)
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

        let proto_report_data = external::EnclaveReportDataContents::from(&report_data);
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

        let proto_report_data = external::EnclaveReportDataContents::from(&report_data);
        let new_report_data =
            EnclaveReportDataContents::try_from(&proto_report_data).expect("failed to convert");

        assert_eq!(report_data, new_report_data);
    }
}
