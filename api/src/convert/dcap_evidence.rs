// Copyright (c) 2023 The MobileCoin Foundation

//! Convert to/from external::DcapEvidence

use crate::{convert::encode_to_protobuf_vec, external, ConversionError};
use mc_attest_verifier_types::{prost, DcapEvidence};
use mc_util_serial::Message;
use protobuf::Message as ProtoMessage;

impl TryFrom<&DcapEvidence> for external::DcapEvidence {
    type Error = ConversionError;
    fn try_from(src: &DcapEvidence) -> Result<Self, Self::Error> {
        let prost = prost::DcapEvidence::try_from(src)?;
        Ok((&prost).into())
    }
}

impl TryFrom<&external::DcapEvidence> for DcapEvidence {
    type Error = ConversionError;
    fn try_from(src: &external::DcapEvidence) -> Result<Self, Self::Error> {
        let prost = prost::DcapEvidence::try_from(src)?;
        Ok((&prost).try_into()?)
    }
}

impl From<&prost::DcapEvidence> for external::DcapEvidence {
    fn from(src: &prost::DcapEvidence) -> Self {
        let bytes = src.encode_to_vec();
        let mut proto = Self::default();
        proto
            .merge_from_bytes(&bytes)
            .expect("failure to merge means prost and protobuf are out of sync");
        proto
    }
}

impl TryFrom<&external::DcapEvidence> for prost::DcapEvidence {
    type Error = ConversionError;
    fn try_from(src: &external::DcapEvidence) -> Result<Self, Self::Error> {
        let bytes = encode_to_protobuf_vec(src)?;
        Ok(prost::DcapEvidence::decode(bytes.as_slice())?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;
    use mc_attest_untrusted::DcapQuotingEnclave;
    use mc_attest_verifier_types::EnclaveReportDataContents;
    use mc_sgx_core_types::Report;

    fn evidence() -> DcapEvidence {
        let report_data = EnclaveReportDataContents::new(
            [0x1au8; 16].into(),
            [0x50u8; 32].as_slice().try_into().expect("bad key"),
            [0x34u8; 32],
        );
        let mut report = Report::default();
        report.as_mut().body.report_data.d[..32].copy_from_slice(&report_data.sha256());

        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to create quote");
        let collateral = DcapQuotingEnclave::collateral(&quote).expect("Failed to get collateral");
        DcapEvidence {
            quote,
            collateral,
            report_data,
        }
    }

    #[test]
    fn evidence_back_and_forth() {
        let evidence = evidence();
        let proto_evidence = external::DcapEvidence::try_from(&evidence)
            .expect("Failed to convert evidence to proto");
        let new_evidence = DcapEvidence::try_from(&proto_evidence)
            .expect("Failed to convert proto evidence to evidence");

        assert_eq!(evidence, new_evidence);
    }

    #[test]
    fn bad_evidence_fails_to_decode() {
        let evidence = evidence();
        let mut proto_evidence = external::DcapEvidence::try_from(&evidence)
            .expect("Failed to convert evidence to proto");
        let proto_quote = proto_evidence.mut_quote();
        proto_quote.data[0] += 1;
        let error = DcapEvidence::try_from(&proto_evidence);

        assert_matches!(error, Err(ConversionError::InvalidContents));
    }
}
