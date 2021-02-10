// Copyright 2018-2020 The MobileCoin Foundation

//! Convert to/from external::VerificationReport

use crate::external;
use mc_attest_core::{VerificationReport, VerificationSignature};
use protobuf::RepeatedField;

impl From<&VerificationReport> for external::VerificationReport {
    fn from(src: &VerificationReport) -> Self {
        let mut dst = external::VerificationReport::new();

        dst.set_sig((&src.sig).into());
        dst.set_chain(RepeatedField::from_slice(&src.chain));
        dst.set_http_body(src.http_body.clone());
        dst
    }
}

impl From<&external::VerificationReport> for VerificationReport {
    fn from(src: &external::VerificationReport) -> Self {
        VerificationReport {
            sig: VerificationSignature::from(src.get_sig()),
            chain: src.get_chain().to_vec(),
            http_body: src.get_http_body().to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IAS_JSON: &str = include_str!("ias_ok.json");

    /// Test round-trip conversion of prost to protobuf to prost
    #[test]
    fn prost_to_proto_roundtrip() {
        let report = VerificationReport {
            sig: VerificationSignature::from(&b"this is a fake signature"[..]),
            chain: pem::parse_many(mc_crypto_x509_test_vectors::ok_rsa_chain_25519_leaf().0)
                .into_iter()
                .map(|p| p.contents)
                .collect::<Vec<Vec<u8>>>(),
            http_body: IAS_JSON.to_owned(),
        };

        // external -> prost
        let proto_report = external::VerificationReport::from(&report);
        // prost -> external
        let prost_report = VerificationReport::from(&proto_report);

        assert_eq!(report, prost_report);
    }
}
