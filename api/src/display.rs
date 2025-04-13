// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Character encodings for public addresses and request types for easy
//! cut-and-paste.

use crate::printable;
use crc::Crc;
use displaydoc::Display;
use prost::Message;

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

impl std::error::Error for Error {}

/// A little-endian IEEE CRC32 checksum is prepended to payloads.
/// Since this is public information with a possibility of transcription
/// failure, a checksum is more appropriate than a hash function
fn calculate_checksum(data: &[u8]) -> [u8; 4] {
    Crc::<u32>::new(&crc::CRC_32_ISO_HDLC)
        .checksum(data)
        .to_le_bytes()
}

/// The B58 wrapper supports encoding the protocol buffer bytes as a b58
/// encoded string, with a checksum prepended to it.
impl printable::PrintableWrapper {
    /// Converts the proto to bytes and then encodes as b58
    pub fn b58_encode(&self) -> Result<String, Error> {
        let wrapper_bytes = self.encode_to_vec();
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
        let wrapper = Self::decode(wrapper_bytes.as_slice())
            .map_err(|err| Error::Deserialization(err.to_string()))?;
        Ok(wrapper)
    }
}

#[cfg(test)]
mod display_tests {
    use super::Error;
    use crate::{
        external,
        printable::{printable_wrapper, PaymentRequest, PrintableWrapper, TransferPayload},
    };
    use mc_test_vectors_b58_encodings::{
        B58EncodePublicAddressWithFog, B58EncodePublicAddressWithoutFog,
    };
    use mc_util_test_vector::TestVector;
    use mc_util_test_with_data::test_with_data;

    fn sample_public_address() -> external::PublicAddress {
        external::PublicAddress {
            view_public_key: Some(external::CompressedRistretto {
                data: vec![1u8; 32],
            }),
            spend_public_key: Some(external::CompressedRistretto {
                data: vec![1u8; 32],
            }),
            fog_report_url: "mob://fog.example.com".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_public_address_roundtrip() {
        let public_address = sample_public_address();

        let wrapper = PrintableWrapper {
            wrapper: Some(printable_wrapper::Wrapper::PublicAddress(public_address)),
        };
        let encoded = wrapper.b58_encode().unwrap();
        let decoded = PrintableWrapper::b58_decode(encoded).unwrap();
        assert_eq!(wrapper, decoded);
    }

    fn printable_wrapper_from_b58_encode_public_address_without_fog(
        case: &B58EncodePublicAddressWithoutFog,
    ) -> PrintableWrapper {
        let public_address = external::PublicAddress {
            view_public_key: Some(external::CompressedRistretto {
                data: case.view_public_key.to_vec(),
            }),
            spend_public_key: Some(external::CompressedRistretto {
                data: case.spend_public_key.to_vec(),
            }),
            ..Default::default()
        };
        PrintableWrapper {
            wrapper: Some(printable_wrapper::Wrapper::PublicAddress(public_address)),
        }
    }

    #[test_with_data(B58EncodePublicAddressWithoutFog::from_jsonl("../test-vectors/vectors"))]
    fn test_b58_encode_public_address_without_fog(case: B58EncodePublicAddressWithoutFog) {
        let wrapper = printable_wrapper_from_b58_encode_public_address_without_fog(&case);
        assert_eq!(wrapper.b58_encode().unwrap(), case.b58_encoded);
    }

    #[test_with_data(B58EncodePublicAddressWithoutFog::from_jsonl("../test-vectors/vectors"))]
    fn test_b58_decode_public_address_without_fog(case: B58EncodePublicAddressWithoutFog) {
        let decoded_wrapper = PrintableWrapper::b58_decode(case.b58_encoded.clone()).unwrap();
        let expected = printable_wrapper_from_b58_encode_public_address_without_fog(&case);
        assert_eq!(decoded_wrapper, expected);
    }

    fn printable_wrapper_from_b58_encode_public_address_with_fog(
        case: &B58EncodePublicAddressWithFog,
    ) -> PrintableWrapper {
        let public_address = external::PublicAddress {
            view_public_key: Some(external::CompressedRistretto {
                data: case.view_public_key.to_vec(),
            }),
            spend_public_key: Some(external::CompressedRistretto {
                data: case.spend_public_key.to_vec(),
            }),
            fog_report_url: case.fog_report_url.clone(),
            fog_report_id: case.fog_report_id.clone(),
            fog_authority_sig: case.fog_authority_sig.clone(),
        };

        PrintableWrapper {
            wrapper: Some(printable_wrapper::Wrapper::PublicAddress(public_address)),
        }
    }

    #[test_with_data(B58EncodePublicAddressWithFog::from_jsonl("../test-vectors/vectors"))]
    fn test_b58_encode_public_address_with_fog(case: B58EncodePublicAddressWithFog) {
        let wrapper = printable_wrapper_from_b58_encode_public_address_with_fog(&case);
        assert_eq!(wrapper.b58_encode().unwrap(), case.b58_encoded);
    }

    #[test_with_data(B58EncodePublicAddressWithFog::from_jsonl("../test-vectors/vectors"))]
    fn test_b58_decode_public_address_with_fog(case: B58EncodePublicAddressWithFog) {
        let decoded_wrapper = PrintableWrapper::b58_decode(case.b58_encoded.clone()).unwrap();
        let expected = printable_wrapper_from_b58_encode_public_address_with_fog(&case);
        assert_eq!(decoded_wrapper, expected);
    }

    #[test]
    fn test_payment_request_roundtrip() {
        let public_address = sample_public_address();

        let payment_request = PaymentRequest {
            public_address: Some(public_address.clone()),
            value: 10,
            memo: "Please me pay!".to_string(),
            ..Default::default()
        };

        let wrapper = PrintableWrapper {
            wrapper: Some(printable_wrapper::Wrapper::PaymentRequest(payment_request)),
        };
        let encoded = wrapper.b58_encode().unwrap();
        let decoded = PrintableWrapper::b58_decode(encoded).unwrap();
        assert_eq!(wrapper, decoded);
    }

    #[test]
    fn test_transfer_payload_roundtrip() {
        #[allow(deprecated)]
        let transfer_payload = TransferPayload {
            root_entropy: vec![1u8; 32],
            tx_out_public_key: Some(external::CompressedRistretto {
                data: vec![2u8; 32],
            }),
            bip39_entropy: vec![12u8; 32],
            ..Default::default()
        };

        let wrapper = PrintableWrapper {
            wrapper: Some(printable_wrapper::Wrapper::TransferPayload(
                transfer_payload.clone(),
            )),
        };
        let encoded = wrapper.b58_encode().unwrap();
        let decoded = PrintableWrapper::b58_decode(encoded).unwrap();
        assert_eq!(wrapper, decoded);
    }

    #[test]
    fn test_bad_checksum() {
        let public_address = sample_public_address();

        let wrapper = PrintableWrapper {
            wrapper: Some(printable_wrapper::Wrapper::PublicAddress(public_address)),
        };
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
