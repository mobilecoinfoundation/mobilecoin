// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::VerificationReport

use crate::external;
use mc_attest_verifier_types::VerificationReport;

impl From<&VerificationReport> for external::VerificationReport {
    fn from(src: &VerificationReport) -> Self {
        let mut dst = external::VerificationReport::new();

        dst.set_sig((&src.sig).into());
        dst.set_chain(src.chain.as_slice().into());
        dst.set_http_body(src.http_body.clone());
        dst
    }
}

impl From<&external::VerificationReport> for VerificationReport {
    fn from(src: &external::VerificationReport) -> Self {
        VerificationReport {
            sig: src.get_sig().into(),
            chain: src.get_chain().to_vec(),
            http_body: src.get_http_body().to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IAS_JSON: &str = include_str!("../../tests/data/ias_ok.json");

    /// Test round-trip conversion of prost to protobuf to prost
    #[test]
    fn prost_to_proto_roundtrip() {
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
        let prost_report = VerificationReport::from(&proto_report);

        assert_eq!(report, prost_report);
    }
}
