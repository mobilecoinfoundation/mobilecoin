// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::VerificationSignature

use crate::external;
use mc_attest_verifier_types::VerificationSignature;

impl From<&VerificationSignature> for external::VerificationSignature {
    fn from(src: &VerificationSignature) -> Self {
        Self {
            contents: src.as_ref().to_vec(),
        }
    }
}

impl From<&external::VerificationSignature> for VerificationSignature {
    fn from(src: &external::VerificationSignature) -> Self {
        src.contents.as_slice().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test round-trip conversion of prost to protobuf to prost
    #[test]
    fn round_trip() {
        let sig = VerificationSignature::from(&b"this is a fake signature"[..]);

        // external -> prost
        let proto_sig = external::VerificationSignature::from(&sig);
        // prost -> external
        let prost_sig = VerificationSignature::from(&proto_sig);

        assert_eq!(sig, prost_sig);
    }
}
