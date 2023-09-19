// Copyright (c) 2023 The MobileCoin Foundation

//! Convert to/from attest::Collateral

use crate::{attest, ConversionError};
use mc_attest_verifier_types::prost;
use mc_sgx_dcap_types::Collateral;
use mc_util_serial::Message;
use protobuf::{CodedOutputStream, Message as ProtoMessage};

impl TryFrom<&Collateral> for attest::Collateral {
    type Error = ConversionError;
    fn try_from(src: &Collateral) -> Result<Self, Self::Error> {
        let prost = prost::Collateral::try_from(src)?;
        let bytes = prost.encode_to_vec();
        let mut proto = Self::default();
        proto
            .merge_from_bytes(&bytes)
            .expect("failure to merge means prost and protobuf are out of sync");
        Ok(proto)
    }
}

impl TryFrom<&attest::Collateral> for Collateral {
    type Error = ConversionError;
    fn try_from(src: &attest::Collateral) -> Result<Self, Self::Error> {
        let bytes = encode_to_protobuf_vec(src)?;
        let prost = prost::Collateral::decode(bytes.as_slice())?;
        prost.try_into()
    }
}

/// Encode a protobuf type to the protobuf representation.
///
/// This makes it easy to convert from a protobuf to a rust type by way of a
/// prost implementation. While this requires converting to a protobuf stream
/// and back again, this allows for placing most of the complex logic in the
/// `prost` implementation and keeping the local `try_from` implementations
/// simple.
///
/// For example:
/// ```ignore
///     let bytes = encode_to_protobuf_vec(proto_type)?;
///     let prost = prost::TYPENAME::decode(bytes.as_slice())?;
///     let rust_type = TYPENAME::try_from(prost)?;
/// ```
pub fn encode_to_protobuf_vec<T: ProtoMessage>(msg: &T) -> Result<Vec<u8>, ConversionError> {
    let mut bytes = vec![];
    let mut stream = CodedOutputStream::vec(&mut bytes);
    msg.write_to_with_cached_sizes(&mut stream)
        .map_err(|e| ConversionError::Other(e.to_string()))?;
    stream
        .flush()
        .map_err(|e| ConversionError::Other(e.to_string()))?;
    Ok(bytes)
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;
    use mc_attest_untrusted::DcapQuotingEnclave;
    use mc_sgx_core_types::Report;

    #[test]
    fn collateral_back_and_forth() {
        let report = Report::default();
        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to create quote");
        let collateral = DcapQuotingEnclave::collateral(&quote);
        let proto_collateral = attest::Collateral::try_from(&collateral)
            .expect("Failed to convert collateral to proto");
        let new_collateral = Collateral::try_from(&proto_collateral)
            .expect("Failed to convert proto collateral to collateral");

        assert_eq!(collateral, new_collateral);
    }

    #[test]
    fn bad_collateral_fails_to_decode() {
        let report = Report::default();
        let quote = DcapQuotingEnclave::quote_report(&report).expect("Failed to create quote");
        let collateral = DcapQuotingEnclave::collateral(&quote);
        let mut proto_collateral = attest::Collateral::try_from(&collateral)
            .expect("Failed to convert collateral to proto");
        proto_collateral.root_ca_crl[0] += 1;
        let error = Collateral::try_from(&proto_collateral);

        assert_matches!(error, Err(ConversionError::InvalidContents(_)));
    }
}
