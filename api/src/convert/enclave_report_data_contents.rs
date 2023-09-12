// Copyright (c) 2023 The MobileCoin Foundation

//! Convert to/from external::EnclaveReportDataContents

use crate::{external, ConversionError};
use mc_attest_verifier_types::EnclaveReportDataContents;
use mc_crypto_keys::X25519Public;
use mc_sgx_core_types::QuoteNonce;

impl From<&EnclaveReportDataContents> for external::EnclaveReportDataContents {
    fn from(src: &EnclaveReportDataContents) -> Self {
        let mut dst = Self::new();

        dst.set_nonce(<QuoteNonce as AsRef<[u8]>>::as_ref(src.nonce()).to_vec());
        dst.set_key(<X25519Public as AsRef<[u8]>>::as_ref(src.key()).to_vec());
        if let Some(custom_identity) = src.custom_identity() {
            dst.set_custom_identity(custom_identity.to_vec());
        }
        dst
    }
}

impl TryFrom<&external::EnclaveReportDataContents> for EnclaveReportDataContents {
    type Error = ConversionError;
    fn try_from(src: &external::EnclaveReportDataContents) -> Result<Self, Self::Error> {
        let nonce: QuoteNonce = src
            .get_nonce()
            .try_into()
            .map_err(|_| ConversionError::InvalidContents)?;
        let key: X25519Public = src.get_key().try_into()?;
        let custom_identity_bytes = src.get_custom_identity().to_vec();
        let custom_identity = if custom_identity_bytes.is_empty() {
            None
        } else {
            Some(
                custom_identity_bytes
                    .try_into()
                    .map_err(|_| ConversionError::InvalidContents)?,
            )
        };
        Ok(EnclaveReportDataContents::new(nonce, key, custom_identity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prost_to_proto_roundtrip() {
        let report_data = EnclaveReportDataContents::new(
            [0x32u8; 16].into(),
            [0x77u8; 32].as_slice().try_into().expect("bad key"),
            [0xCCu8; 32],
        );

        let proto_report_data = external::EnclaveReportDataContents::from(&report_data);
        let prost_report_data =
            EnclaveReportDataContents::try_from(&proto_report_data).expect("failed to convert");

        assert_eq!(report_data, prost_report_data);
    }

    #[test]
    fn prost_to_proto_roundtrip_no_custom_id() {
        let report_data = EnclaveReportDataContents::new(
            [0x32u8; 16].into(),
            [0x77u8; 32].as_slice().try_into().expect("bad key"),
            None,
        );

        let proto_report_data = external::EnclaveReportDataContents::from(&report_data);
        let prost_report_data =
            EnclaveReportDataContents::try_from(&proto_report_data).expect("failed to convert");

        assert_eq!(report_data, prost_report_data);
    }
}
