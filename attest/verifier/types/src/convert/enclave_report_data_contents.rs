// Copyright (c) 2023 The MobileCoin Foundation

//! Conversions from prost message type into common crate rust types.
use crate::{prost, ConversionError, EnclaveReportDataContents};
use alloc::string::ToString;
use mc_crypto_keys::X25519Public;
use mc_sgx_core_types::QuoteNonce;

impl TryFrom<prost::EnclaveReportDataContents> for EnclaveReportDataContents {
    type Error = ConversionError;

    fn try_from(value: prost::EnclaveReportDataContents) -> Result<Self, Self::Error> {
        let nonce: QuoteNonce =
            value
                .nonce
                .as_slice()
                .try_into()
                .map_err(|_| ConversionError::LengthMismatch {
                    name: "nonce".to_string(),
                    provided: value.nonce.len(),
                    required: QuoteNonce::SIZE,
                })?;
        let key: X25519Public = value.key.as_slice().try_into()?;
        let custom_identity_bytes = value.custom_identity;
        let custom_identity = if custom_identity_bytes.is_empty() {
            None
        } else {
            Some(custom_identity_bytes.as_slice().try_into().map_err(|_| {
                ConversionError::LengthMismatch {
                    name: "custom_identity".to_string(),
                    provided: custom_identity_bytes.len(),
                    required: 32,
                }
            })?)
        };
        Ok(EnclaveReportDataContents::new(nonce, key, custom_identity))
    }
}

impl From<&EnclaveReportDataContents> for prost::EnclaveReportDataContents {
    fn from(value: &EnclaveReportDataContents) -> Self {
        let nonce_bytes: &[u8] = value.nonce().as_ref();
        let key_bytes: &[u8] = value.key().as_ref();
        prost::EnclaveReportDataContents {
            nonce: nonce_bytes.to_vec(),
            key: key_bytes.to_vec(),
            custom_identity: value
                .custom_identity()
                .map(|id| id.to_vec())
                .unwrap_or_default(),
        }
    }
}
use mc_crypto_digestible::{DigestTranscript, Digestible};

impl Digestible for prost::EnclaveReportDataContents {
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        let typename = b"EnclaveReportDataContents";
        transcript.append_agg_header(context, typename);
        transcript.append_primitive(context, b"nonce", &self.nonce);
        transcript.append_primitive(context, b"key", &self.key);
        // Since custom identity is optional we only include it if it has data.
        if !self.custom_identity.is_empty() {
            transcript.append_primitive(context, b"custom_identity", &self.custom_identity);
        }
        transcript.append_agg_closer(context, typename);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use assert_matches::assert_matches;
    use mc_crypto_digestible::MerlinTranscript;

    #[test]
    fn prost_roundtrip() {
        let report_data = EnclaveReportDataContents::new(
            [0xAFu8; 16].into(),
            [0x66u8; 32].as_slice().try_into().expect("bad key"),
            [0x32u8; 32],
        );

        let prost_report_data = prost::EnclaveReportDataContents::from(&report_data);
        let new_report_data =
            EnclaveReportDataContents::try_from(prost_report_data).expect("failed to convert");

        assert_eq!(report_data, new_report_data);
    }

    #[test]
    fn prost_roundtrip_no_custom_id() {
        let report_data = EnclaveReportDataContents::new(
            [0x18u8; 16].into(),
            [0x52u8; 32].as_slice().try_into().expect("bad key"),
            None,
        );

        let prost_report_data = prost::EnclaveReportDataContents::from(&report_data);
        let new_report_data =
            EnclaveReportDataContents::try_from(prost_report_data).expect("failed to convert");

        assert_eq!(report_data, new_report_data);
    }

    #[test]
    fn prost_fails_for_wrong_sized_quote_nonce() {
        let report_data = EnclaveReportDataContents::new(
            [0x18u8; 16].into(),
            [0x52u8; 32].as_slice().try_into().expect("bad key"),
            [0x32u8; 32],
        );

        let mut prost_report_data = prost::EnclaveReportDataContents::from(&report_data);
        let _ = prost_report_data.nonce.pop();
        let error = EnclaveReportDataContents::try_from(prost_report_data);

        assert_matches!(error, Err(ConversionError::LengthMismatch { .. }));
    }

    #[test]
    fn prost_fails_for_bad_key() {
        let report_data = EnclaveReportDataContents::new(
            [0x18u8; 16].into(),
            [0x52u8; 32].as_slice().try_into().expect("bad key"),
            [0x32u8; 32],
        );

        let mut prost_report_data = prost::EnclaveReportDataContents::from(&report_data);
        let _ = prost_report_data.key.pop();
        let error = EnclaveReportDataContents::try_from(prost_report_data);

        assert_matches!(error, Err(ConversionError::Key(_)));
    }

    #[test]
    fn prost_fails_for_malformed_custom_id() {
        let report_data = EnclaveReportDataContents::new(
            [0x18u8; 16].into(),
            [0x52u8; 32].as_slice().try_into().expect("bad key"),
            [0x32u8; 32],
        );

        let mut prost_report_data = prost::EnclaveReportDataContents::from(&report_data);
        prost_report_data.custom_identity.push(0x12);
        let error = EnclaveReportDataContents::try_from(prost_report_data);

        assert_matches!(error, Err(ConversionError::LengthMismatch { .. }));
    }

    #[test]
    fn enclave_report_data_contents_digest() {
        let nonce_bytes = [0x1u8; 16];
        let key_bytes = [0x22u8; 32];
        let custom_identity = [0x33u8; 32];
        let report_data_1 = prost::EnclaveReportDataContents {
            nonce: nonce_bytes.to_vec(),
            key: key_bytes.to_vec(),
            custom_identity: custom_identity.to_vec(),
        };

        let report_data_2 = prost::EnclaveReportDataContents {
            nonce: nonce_bytes.to_vec(),
            key: key_bytes.to_vec(),
            custom_identity: custom_identity.to_vec(),
        };

        let digest_1 = report_data_1.digest32::<MerlinTranscript>(b"");
        let digest_2 = report_data_2.digest32::<MerlinTranscript>(b"");
        assert_eq!(digest_1, digest_2);

        let mut modified_nonce = nonce_bytes.to_vec();
        modified_nonce[0] += 1;
        let modified_nonce_report_data = prost::EnclaveReportDataContents {
            nonce: modified_nonce,
            key: key_bytes.to_vec(),
            custom_identity: custom_identity.to_vec(),
        };

        let modified_nonce_digest = modified_nonce_report_data.digest32::<MerlinTranscript>(b"");
        assert_ne!(digest_1, modified_nonce_digest);

        let mut modified_key_bytes = key_bytes.to_vec();
        modified_key_bytes[0] += 1;
        let modified_key_report_data = prost::EnclaveReportDataContents {
            nonce: nonce_bytes.to_vec(),
            key: modified_key_bytes,
            custom_identity: custom_identity.to_vec(),
        };

        let modified_key_digest = modified_key_report_data.digest32::<MerlinTranscript>(b"");
        assert_ne!(digest_1, modified_key_digest);

        let mut modified_custom_identity = custom_identity.to_vec();
        modified_custom_identity[0] += 1;
        let modified_custom_identity_report_data = prost::EnclaveReportDataContents {
            nonce: nonce_bytes.to_vec(),
            key: key_bytes.to_vec(),
            custom_identity: modified_custom_identity,
        };

        let modified_custom_identity_digest =
            modified_custom_identity_report_data.digest32::<MerlinTranscript>(b"");
        assert_ne!(digest_1, modified_custom_identity_digest);
    }

    #[test]
    fn enclave_report_data_contents_digest_without_custom_id() {
        let nonce_bytes = [0x2u8; 16];
        let key_bytes = [0x33u8; 32];
        let zeroed_custom_identity = [0x0u8; 32];
        let report_data_without_custom_id = prost::EnclaveReportDataContents {
            nonce: nonce_bytes.to_vec(),
            key: key_bytes.to_vec(),
            custom_identity: vec![],
        };

        let report_data_with_zeroed_custom_id = prost::EnclaveReportDataContents {
            nonce: nonce_bytes.to_vec(),
            key: key_bytes.to_vec(),
            custom_identity: zeroed_custom_identity.to_vec(),
        };

        let no_custom_id_digest = report_data_without_custom_id.digest32::<MerlinTranscript>(b"");
        let zeroed_custom_id_digest =
            report_data_with_zeroed_custom_id.digest32::<MerlinTranscript>(b"");
        assert_ne!(no_custom_id_digest, zeroed_custom_id_digest);
    }
}
