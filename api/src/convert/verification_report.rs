// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::VerificationReport

use crate::{external, ConversionError};
use mc_attest_verifier_types::VerificationReport;

impl From<&VerificationReport> for external::VerificationReport {
    fn from(src: &VerificationReport) -> Self {
        Self {
            sig: Some((&src.sig).into()),
            chain: src.chain.clone(),
            http_body: src.http_body.clone(),
        }
    }
}

impl TryFrom<&external::VerificationReport> for VerificationReport {
    type Error = ConversionError;

    fn try_from(src: &external::VerificationReport) -> Result<Self, Self::Error> {
        let sig = src
            .sig
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        Ok(Self {
            sig,
            chain: src.chain.to_vec(),
            http_body: src.http_body.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IAS_JSON: &str = include_str!("../../tests/data/ias_ok.json");

    /// Test round-trip conversion of prost to protobuf to prost
    #[test]
    fn round_trip() {
        let report = VerificationReport {
            sig: b"this is a fake signature".as_slice().into(),
            chain: pem::parse_many(mc_crypto_x509_test_vectors::ok_rsa_chain_25519_leaf().0)
                .expect("Could not parse PEM input")
                .into_iter()
                .map(|p| p.contents)
                .collect(),
            http_body: IAS_JSON.to_owned(),
        };

        // external -> prost
        let proto_report = external::VerificationReport::from(&report);
        // prost -> external
        let prost_report = VerificationReport::try_from(&proto_report).unwrap();

        assert_eq!(report, prost_report);
    }
}
