// Copyright (c) 2023 The MobileCoin Foundation

//! Convert to/from external::DcapEvidence

use crate::{external, ConversionError};
use mc_attest_verifier_types::DcapEvidence;
use mc_sgx_dcap_types::{Collateral, Quote3};

impl From<&DcapEvidence> for external::DcapEvidence {
    fn from(src: &DcapEvidence) -> Self {
        let mut dst = Self::new();

        let quote = mc_util_serial::serialize(&src.quote).expect("Invalid Dcap Evidence");
        dst.set_quote(quote);
        let collateral = mc_util_serial::serialize(&src.collateral).expect("Invalid Dcap Evidence");
        dst.set_collateral(collateral);
        if let Some(report_data) = &src.report_data {
            dst.set_enclave_report_data_contents(report_data.into());
        }
        dst
    }
}

impl TryFrom<&external::DcapEvidence> for DcapEvidence {
    type Error = ConversionError;
    fn try_from(src: &external::DcapEvidence) -> Result<Self, Self::Error> {
        let quote: Option<Quote3<Vec<u8>>> = mc_util_serial::deserialize(src.get_quote())
            .map_err(|_| ConversionError::InvalidContents)?;
        if quote.is_none() {
            return Err(ConversionError::MissingField("quote".to_string()));
        }
        let collateral: Option<Collateral> = mc_util_serial::deserialize(src.get_collateral())
            .map_err(|_| ConversionError::InvalidContents)?;
        if collateral.is_none() {
            return Err(ConversionError::MissingField("collateral".to_string()));
        }
        if !src.has_enclave_report_data_contents() {
            return Err(ConversionError::MissingField("report_data".to_string()));
        }
        let report_data = src.get_enclave_report_data_contents();
        Ok(DcapEvidence {
            quote,
            collateral,
            report_data: Some(report_data.try_into()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Testing for conversion of a valid DcapEvidence is done in
    // `attest/untrusted/src/sim.rs` due to the complexity of creating a quote
    // and collateral.
    #[test]
    fn default_dcap_evidence_fails_from_partial_proto() {
        // We create a default DcapEvidence, which sets all the members to `None`.
        // This isn't a valid DcapEvidence, so we expect the conversion to fail if we
        // ever see this in the wild.
        let evidence = DcapEvidence::default();
        let proto_evidence = external::DcapEvidence::from(&evidence);
        let result = DcapEvidence::try_from(&proto_evidence);
        assert!(result.is_err());
    }
}
