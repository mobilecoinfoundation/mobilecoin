// Copyright (c) 2018-2020 MobileCoin Inc.

//! Character encodings for public addresses and request types for easy
//! cut-and-paste.

use crate::printable;
use crc::crc32;
use displaydoc::Display;
use protobuf::{parse_from_bytes, Message};

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
/// Since this is public information with a possibility of transcription failure,
/// a checksum is more appropriate than a hash function
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
        let wrapper = parse_from_bytes(&wrapper_bytes)
            .map_err(|err| Error::Deserialization(err.to_string()))?;
        Ok(wrapper)
    }
}

#[cfg(test)]
mod display_tests {
    use super::Error;
    use crate::{
        external,
        printable::{PaymentRequest, PrintableWrapper},
    };

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

    #[test]
    fn test_payment_request_roundtrip() {
        let public_address = sample_public_address();

        let mut payment_request = PaymentRequest::new();
        payment_request.set_public_address(public_address);
        payment_request.set_amount(10);
        payment_request.set_memo("Please me pay!".to_string());

        let mut wrapper = PrintableWrapper::new();
        wrapper.set_payment_request(payment_request);
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
