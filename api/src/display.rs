// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Character encodings for public addresses and request types for easy
//! cut-and-paste.

use crate::printable;
use crc::crc32;
use displaydoc::Display;
use protobuf::Message;

/// Decoding / encoding errors
#[derive(Clone, Debug, Eq, PartialEq, Display)]
pub enum Error {
    /// Protobuf serialization error: {0}
    Serialization(String),

    /// B58 Decoding error: {0}
    B58(String),

    /// Protobuf deserialization error: {0}
    Deserialization(String),

    /// Checksum does not match
    ChecksumMismatch,

    /// Not enough bytes in the decoded vector {0}
    InsufficientBytes(usize),
}

/// A little-endian IEEE CRC32 checksum is prepended to payloads.
/// Since this is public information with a possibility of transcription
/// failure, a checksum is more appropriate than a hash function
fn calculate_checksum(data: &[u8]) -> [u8; 4] {
    crc32::checksum_ieee(data).to_le_bytes()
}

/// The B58 wrapper supports encoding the protocol buffer bytes as a b58
/// encoded string, with a checksum prepended to it.
impl printable::PrintableWrapper {
    /// Converts the proto to bytes and then encodes as b58
    pub fn b58_encode(&self) -> Result<String, Error> {
        let wrapper_bytes = self
            .write_to_bytes()
            .map_err(|err| Error::Serialization(err.to_string()))?;
        let mut bytes_vec = Vec::new();
        bytes_vec.extend_from_slice(&calculate_checksum(&wrapper_bytes));
        bytes_vec.extend_from_slice(&wrapper_bytes);
        Ok(bs58::encode(&bytes_vec[..]).into_string())
    }

    /// Converts a b58 string to bytes and then decodes to a proto
    pub fn b58_decode(encoded: String) -> Result<Self, Error> {
        let mut decoded_bytes = bs58::decode(encoded)
            .into_vec()
            .map_err(|err| Error::B58(err.to_string()))?;
        if decoded_bytes.len() < 5 {
            return Err(Error::InsufficientBytes(decoded_bytes.len()));
        }
        let wrapper_bytes = decoded_bytes.split_off(4);
        let expected_checksum = calculate_checksum(&wrapper_bytes);
        if expected_checksum.to_vec() != decoded_bytes {
            return Err(Error::ChecksumMismatch);
        }
        let wrapper = Self::parse_from_bytes(&wrapper_bytes)
            .map_err(|err| Error::Deserialization(err.to_string()))?;
        Ok(wrapper)
    }
}

#[cfg(test)]
mod display_tests {
    use super::Error;
    use crate::{
        external,
        printable::{PaymentRequest, PrintableWrapper, TransferPayload},
    };
    use datatest::data;
    use mc_test_vectors_b58_encodings::*;
    use mc_util_test_vector::TestVector;

    fn sample_public_address() -> external::PublicAddress {
        let mut public_address = external::PublicAddress::new();

        let mut view_bytes = external::CompressedRistretto::new();
        view_bytes.set_data(vec![1u8; 32]);
        public_address.set_view_public_key(view_bytes);

        let mut spend_bytes = external::CompressedRistretto::new();
        spend_bytes.set_data(vec![1u8; 32]);
        public_address.set_spend_public_key(spend_bytes);

        public_address.set_fog_report_url("mob://fog.example.com".to_string());
        public_address
    }

    #[test]
    fn test_public_address_roundtrip() {
        let public_address = sample_public_address();

        let mut wrapper = PrintableWrapper::new();
        wrapper.set_public_address(public_address);
        let encoded = wrapper.b58_encode().unwrap();
        let decoded = PrintableWrapper::b58_decode(encoded).unwrap();
        assert_eq!(wrapper, decoded);
    }

    fn printable_wrapper_from_b58_encode_public_address_without_fog(
        case: &B58EncodePublicAddressWithoutFog,
    ) -> PrintableWrapper {
        let mut public_address = external::PublicAddress::new();

        let mut view_bytes = external::CompressedRistretto::new();
        view_bytes.set_data(case.view_public_key.to_vec());
        public_address.set_view_public_key(view_bytes);

        let mut spend_bytes = external::CompressedRistretto::new();
        spend_bytes.set_data(case.spend_public_key.to_vec());
        public_address.set_spend_public_key(spend_bytes);

        let mut wrapper = PrintableWrapper::new();
        wrapper.set_public_address(public_address);

        wrapper
    }

    #[data(B58EncodePublicAddressWithoutFog::from_jsonl("../test-vectors/vectors"))]
    #[test]
    fn test_b58_encode_public_address_without_fog(case: B58EncodePublicAddressWithoutFog) {
        let wrapper = printable_wrapper_from_b58_encode_public_address_without_fog(&case);
        assert_eq!(wrapper.b58_encode().unwrap(), case.b58_encoded);
    }

    #[data(B58EncodePublicAddressWithoutFog::from_jsonl("../test-vectors/vectors"))]
    #[test]
    fn test_b58_decode_public_address_without_fog(case: B58EncodePublicAddressWithoutFog) {
        let decoded_wrapper = PrintableWrapper::b58_decode(case.b58_encoded.clone()).unwrap();
        let expected = printable_wrapper_from_b58_encode_public_address_without_fog(&case);
        assert_eq!(decoded_wrapper, expected);
    }

    fn printable_wrapper_from_b58_encode_public_address_with_fog(
        case: &B58EncodePublicAddressWithFog,
    ) -> PrintableWrapper {
        let mut public_address = external::PublicAddress::new();

        let mut view_bytes = external::CompressedRistretto::new();
        view_bytes.set_data(case.view_public_key.to_vec());
        public_address.set_view_public_key(view_bytes);

        let mut spend_bytes = external::CompressedRistretto::new();
        spend_bytes.set_data(case.spend_public_key.to_vec());
        public_address.set_spend_public_key(spend_bytes);

        public_address.set_fog_report_url(case.fog_report_url.clone());
        public_address.set_fog_report_id(case.fog_report_id.clone());
        public_address.set_fog_authority_sig(case.fog_authority_sig.clone());

        let mut wrapper = PrintableWrapper::new();
        wrapper.set_public_address(public_address);

        wrapper
    }

    #[data(B58EncodePublicAddressWithFog::from_jsonl("../test-vectors/vectors"))]
    #[test]
    fn test_b58_encode_public_address_with_fog(case: B58EncodePublicAddressWithFog) {
        let wrapper = printable_wrapper_from_b58_encode_public_address_with_fog(&case);
        assert_eq!(wrapper.b58_encode().unwrap(), case.b58_encoded);
    }

    #[data(B58EncodePublicAddressWithFog::from_jsonl("../test-vectors/vectors"))]
    #[test]
    fn test_b58_decode_public_address_with_fog(case: B58EncodePublicAddressWithFog) {
        let decoded_wrapper = PrintableWrapper::b58_decode(case.b58_encoded.clone()).unwrap();
        let expected = printable_wrapper_from_b58_encode_public_address_with_fog(&case);
        assert_eq!(decoded_wrapper, expected);
    }

    #[test]
    fn test_payment_request_roundtrip() {
        let public_address = sample_public_address();

        let mut payment_request = PaymentRequest::new();
        payment_request.set_public_address(public_address);
        payment_request.set_value(10);
        payment_request.set_memo("Please me pay!".to_string());

        let mut wrapper = PrintableWrapper::new();
        wrapper.set_payment_request(payment_request);
        let encoded = wrapper.b58_encode().unwrap();
        let decoded = PrintableWrapper::b58_decode(encoded).unwrap();
        assert_eq!(wrapper, decoded);
    }

    #[test]
    fn test_transfer_payload_roundtrip() {
        let mut transfer_payload = TransferPayload::new();
        transfer_payload.set_root_entropy(vec![1u8; 32]);
        transfer_payload.set_bip39_entropy(vec![12u8; 32]);
        transfer_payload
            .mut_tx_out_public_key()
            .set_data(vec![2u8; 32]);

        let mut wrapper = PrintableWrapper::new();
        wrapper.set_transfer_payload(transfer_payload);
        let encoded = wrapper.b58_encode().unwrap();
        let decoded = PrintableWrapper::b58_decode(encoded).unwrap();
        assert_eq!(wrapper, decoded);
    }

    #[test]
    fn test_bad_checksum() {
        let public_address = sample_public_address();

        let mut wrapper = PrintableWrapper::new();
        wrapper.set_public_address(public_address);
        let encoded = wrapper.b58_encode().unwrap();

        // Change the checksum
        let mut vec_encoded = bs58::decode(encoded).into_vec().unwrap();
        vec_encoded[0] += 1;
        let reencoded = bs58::encode(vec_encoded).into_string();

        let decoded = PrintableWrapper::b58_decode(reencoded);
        assert_eq!(decoded.err(), Some(Error::ChecksumMismatch));
    }

    #[test]
    fn test_insufficent_bytes() {
        let encoded = "2g".to_string();
        assert_eq!(
            PrintableWrapper::b58_decode(encoded).err(),
            Some(Error::InsufficientBytes(1))
        );
    }
}
