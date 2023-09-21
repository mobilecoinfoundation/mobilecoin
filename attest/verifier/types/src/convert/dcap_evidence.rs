// Copyright (c) 2023 The MobileCoin Foundation

//! Conversions to/from prost::DcapEvidence to DcapEvidence

use crate::{prost, ConversionError, DcapEvidence};
use alloc::string::ToString;
use mc_crypto_digestible::{DigestTranscript, Digestible};

impl TryFrom<prost::DcapEvidence> for DcapEvidence {
    type Error = ConversionError;

    fn try_from(value: prost::DcapEvidence) -> Result<Self, Self::Error> {
        let quote = value
            .quote
            .ok_or_else(|| ConversionError::MissingField("quote".to_string()))?;
        let collateral = value
            .collateral
            .ok_or_else(|| ConversionError::MissingField("collateral".to_string()))?;
        let report_data = value
            .report_data
            .ok_or_else(|| ConversionError::MissingField("report_data".to_string()))?;
        Ok(Self {
            quote: quote.try_into()?,
            collateral: collateral.try_into()?,
            report_data: report_data.try_into()?,
        })
    }
}

impl TryFrom<&DcapEvidence> for prost::DcapEvidence {
    type Error = ConversionError;

    fn try_from(value: &DcapEvidence) -> Result<Self, Self::Error> {
        Ok(Self {
            quote: Some((&value.quote).into()),
            collateral: Some((&value.collateral).try_into()?),
            report_data: Some((&value.report_data).into()),
        })
    }
}

impl Digestible for prost::DcapEvidence {
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        let typename = b"DcapEvidence";
        transcript.append_agg_header(context, typename);

        let Self {
            quote,
            collateral,
            report_data,
        } = self;
        quote.append_to_transcript(context, transcript);
        collateral.append_to_transcript(context, transcript);
        report_data.append_to_transcript(context, transcript);

        transcript.append_agg_closer(context, typename);
    }
}

#[cfg(test)]
mod test {
    use super::{prost, *};
    use crate::EnclaveReportDataContents;
    use ::prost::Message;
    use assert_matches::assert_matches;
    use mc_attest_untrusted::DcapQuotingEnclave;
    use mc_crypto_digestible::MerlinTranscript;
    use mc_sgx_core_types::Report;

    fn evidence() -> DcapEvidence {
        let report_data = EnclaveReportDataContents::new(
            [0x19u8; 16].into(),
            [0x51u8; 32].as_slice().try_into().expect("bad key"),
            [0x33u8; 32],
        );
        let mut report = Report::default();
        report.as_mut().body.report_data.d[..32].copy_from_slice(&report_data.sha256());

        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to create quote");
        let collateral = DcapQuotingEnclave::collateral(&quote);
        DcapEvidence {
            quote,
            collateral,
            report_data,
        }
    }

    #[test]
    fn evidence_back_and_forth() {
        let evidence = evidence();
        let prost_evidence =
            prost::DcapEvidence::try_from(&evidence).expect("Failed to convert evidence to prost");
        let bytes = prost_evidence.encode_to_vec();
        let new_evidence = DcapEvidence::try_from(
            prost::DcapEvidence::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        )
        .expect("Failed to convert prost evidence to evidence");

        assert_eq!(evidence, new_evidence);
    }

    #[test]
    fn evidence_missing_quote() {
        let evidence = evidence();
        let mut prost_evidence =
            prost::DcapEvidence::try_from(&evidence).expect("Failed to convert evidence to prost");
        prost_evidence.quote = None;
        let bytes = prost_evidence.encode_to_vec();
        let error = DcapEvidence::try_from(
            prost::DcapEvidence::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        );

        assert_matches!(error, Err(ConversionError::MissingField(message)) if message.contains("quote"));
    }

    #[test]
    fn evidence_missing_collateral() {
        let evidence = evidence();
        let mut prost_evidence =
            prost::DcapEvidence::try_from(&evidence).expect("Failed to convert evidence to prost");
        prost_evidence.collateral = None;
        let bytes = prost_evidence.encode_to_vec();
        let error = DcapEvidence::try_from(
            prost::DcapEvidence::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        );

        assert_matches!(error, Err(ConversionError::MissingField(message)) if message.contains("collateral"));
    }

    #[test]
    fn evidence_missing_report_data() {
        let evidence = evidence();
        let mut prost_evidence =
            prost::DcapEvidence::try_from(&evidence).expect("Failed to convert evidence to prost");
        prost_evidence.report_data = None;
        let bytes = prost_evidence.encode_to_vec();
        let error = DcapEvidence::try_from(
            prost::DcapEvidence::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        );

        assert_matches!(error, Err(ConversionError::MissingField(message)) if message.contains("report_data"));
    }

    #[test]
    fn evidence_with_corrupt_quote() {
        let evidence = evidence();
        let mut prost_evidence =
            prost::DcapEvidence::try_from(&evidence).expect("Failed to convert evidence to prost");
        let prost_quote = prost_evidence.quote.as_mut().expect("quote should be set");
        prost_quote.data[1] += 1;
        let bytes = prost_evidence.encode_to_vec();
        let error = DcapEvidence::try_from(
            prost::DcapEvidence::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        );

        assert_matches!(error, Err(ConversionError::InvalidContents(_)));
    }

    #[test]
    fn evidence_with_corrupt_collateral() {
        let evidence = evidence();
        let mut prost_evidence =
            prost::DcapEvidence::try_from(&evidence).expect("Failed to convert evidence to prost");
        let prost_collateral = prost_evidence
            .collateral
            .as_mut()
            .expect("collateral should be set");
        prost_collateral.root_ca_crl[0] += 1;
        let bytes = prost_evidence.encode_to_vec();
        let error = DcapEvidence::try_from(
            prost::DcapEvidence::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        );

        assert_matches!(error, Err(ConversionError::InvalidContents(_)));
    }

    #[test]
    fn evidence_with_corrupt_report_data() {
        let evidence = evidence();
        let mut prost_evidence =
            prost::DcapEvidence::try_from(&evidence).expect("Failed to convert evidence to prost");
        let prost_report_data = prost_evidence
            .report_data
            .as_mut()
            .expect("report_data should be set");
        let _ = prost_report_data.custom_identity.pop();
        let bytes = prost_evidence.encode_to_vec();
        let error = DcapEvidence::try_from(
            prost::DcapEvidence::decode(bytes.as_slice()).expect("Failed to decode prost bytes"),
        );

        assert_matches!(error, Err(ConversionError::LengthMismatch { .. }));
    }

    #[test]
    fn digestible() {
        let evidence = evidence();
        let prost_evidence =
            prost::DcapEvidence::try_from(&evidence).expect("Failed to convert evidence to prost");

        // We manually build up the digest here, to help ensure that the digest
        // order of fields is maintained in the future.
        let context = b"history sticks to your feet";

        // The `digestible` byte string is used in the `DigestTranscript`
        // implementation for `MerlinTranscript`. It shouldn't change or else
        // historical digests would fail to be reproduced.
        let mut transcript = MerlinTranscript::new(b"digestible");
        transcript.append_agg_header(context, b"DcapEvidence");

        // As mentioned above the order of these calls should not change after
        // release. Only items added or removed. This is because the digest
        // will be stored on the block chain and someone will need to be able
        // to reproduce it. Note that prost will order the fields in generated
        // code based on tag numbers. This test also helps ensure the order
        // of the prost generated fields.
        prost_evidence
            .quote
            .clone()
            .expect("Quote should be set")
            .append_to_transcript(context, &mut transcript);
        prost_evidence
            .collateral
            .clone()
            .expect("Collateral should be set")
            .append_to_transcript(context, &mut transcript);
        prost_evidence
            .report_data
            .clone()
            .expect("Report data should be set")
            .append_to_transcript(context, &mut transcript);

        transcript.append_agg_closer(context, b"DcapEvidence");

        let mut expected_digest = [0u8; 32];
        transcript.extract_digest(&mut expected_digest);

        let evidence_digest = prost_evidence.digest32::<MerlinTranscript>(context);
        assert_eq!(evidence_digest, expected_digest);
    }
}
