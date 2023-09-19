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

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

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
}
