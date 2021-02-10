// Copyright 2018-2020 The MobileCoin Foundation

//! Convert to/from external::VerificationSignature

use crate::external;
use mc_attest_core::VerificationSignature;

impl From<&VerificationSignature> for external::VerificationSignature {
    fn from(src: &VerificationSignature) -> Self {
        let mut dst = external::VerificationSignature::new();

        dst.set_contents(src.clone().into());
        dst
    }
}

impl From<&external::VerificationSignature> for VerificationSignature {
    fn from(src: &external::VerificationSignature) -> Self {
        VerificationSignature::from(src.get_contents())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test round-trip conversion of prost to protobuf to prost
    #[test]
    fn prost_to_proto_roundtrip() {
        let sig = VerificationSignature::from(&b"this is a fake signature"[..]);

        // external -> prost
        let proto_sig = external::VerificationSignature::from(&sig);
        // prost -> external
        let prost_sig = VerificationSignature::from(&proto_sig);

        assert_eq!(sig, prost_sig);
    }
}
