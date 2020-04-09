// Copyright (c) 2018-2020 MobileCoin Inc.

//! Formats for encoding MobileCoin addresses.

use crate::account_keys::PublicAddress;
use alloc::{
    string::{FromUtf8Error, String},
    vec::Vec,
};
use bs58;
use byteorder::{ByteOrder, LittleEndian};
use core::convert::TryFrom;
use crc::crc32;
use failure::Fail;
use keys::{CompressedRistrettoPublic, KeyError, RistrettoPublic};
use serde::{Deserialize, Serialize};

/// Types of MobileCoin addresses.
enum AddressType {
    PublicAddress = 0,
}
const ENCODING_VERSION: u8 = 1;

/// Address encoding and decoding.
pub trait AddressEncoder: Sized {
    /// Decodes an address.
    fn decode(encoded_address: String) -> Result<Self, AddressParseError>;

    /// Encodes an address.
    fn encode(&self) -> String;
}

/// A collection of errors encountered when parsing address display formats.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Fail, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AddressParseError {
    /// A public key is not a valid Ristretto point.
    #[fail(display = "Parsing failed with key error {:?}", _0)]
    KeyError(KeyError),

    /// Not enough bytes to create an address.
    #[fail(display = "The address is not long enough")]
    InsufficientBytes,

    /// The address is not a valid base58 string.
    #[fail(display = "The address is not a valid base58 string")]
    Base58DecodingError,

    /// Unable to parse FogUrL string.
    #[fail(display = "Unable to parse FogURL string")]
    FogURLParsingError,

    /// Checksum for payload is incorrect.
    #[fail(display = "Checksum for payload is incorrect")]
    ChecksumError,

    /// Encoded string is the wrong type.
    #[fail(display = "Encoded string is the wrong type")]
    TypeMismatchError,
}

impl From<KeyError> for AddressParseError {
    fn from(src: KeyError) -> Self {
        AddressParseError::KeyError(src)
    }
}

impl From<bs58::decode::Error> for AddressParseError {
    fn from(_: bs58::decode::Error) -> Self {
        AddressParseError::Base58DecodingError
    }
}

impl From<FromUtf8Error> for AddressParseError {
    fn from(_: FromUtf8Error) -> Self {
        AddressParseError::FogURLParsingError
    }
}

/// The checksum is prepended to any address data to confirm that there are
/// no typographical errors. Little-endian IEEE CRC32.
fn checksum(data: &[u8]) -> [u8; 4] {
    let checksum = crc32::checksum_ieee(data);
    let mut result = [0; 4];
    LittleEndian::write_u32(&mut result, checksum);
    result
}

impl AddressEncoder for PublicAddress {
    /// Creates a new public address from a string formatted according to the MobileCoin
    /// public address display format
    ///
    /// The address format is a base58 encoded byte array, with bytes:
    /// [0..4]       checksum of entire payload (litte-endian IEEE CRC32)
    /// [4]          type of address (PublicAddress = 0)
    /// [5]          version of address encoding
    /// [6..38]      view key
    /// [38..70]     spend key
    /// [70]         length of FogURL (f)
    /// [71..71+f]   FogURL as utf-8 encoded string
    /// [71+f..]     Potential additional data
    ///
    /// # Arguments
    /// `encoded_address` - A string representing the encoded address
    fn decode(encoded_address: String) -> Result<Self, AddressParseError> {
        let address_bytes = bs58::decode(encoded_address).into_vec()?;
        if address_bytes.len() >= 70 {
            let checksum = checksum(&address_bytes[4..]);
            if checksum != address_bytes[0..4] {
                return Err(AddressParseError::ChecksumError);
            }
            if address_bytes[4] != (AddressType::PublicAddress as u8) {
                return Err(AddressParseError::TypeMismatchError);
            }
            let view_key = RistrettoPublic::try_from(&address_bytes[6..38])?;
            let spend_key = RistrettoPublic::try_from(&address_bytes[38..70])?;
            if address_bytes.len() == 70 {
                Ok(Self::new(&spend_key, &view_key))
            } else {
                let fqdn_len = address_bytes[70] as usize;
                if address_bytes.len() < 71 + fqdn_len {
                    return Err(AddressParseError::InsufficientBytes);
                }
                let fog_url_bytes = &address_bytes[71..(71 + fqdn_len)];
                let fog_url = String::from_utf8(fog_url_bytes.to_vec())?;
                Ok(Self::new_with_fog(&spend_key, &view_key, fog_url))
            }
        } else {
            Err(AddressParseError::InsufficientBytes)
        }
    }

    /// Encodes this public address to a string. See `decode` above for details
    /// on the encoding.
    fn encode(&self) -> String {
        let mut encoded_vec = Vec::new();

        encoded_vec.push(AddressType::PublicAddress as u8);
        encoded_vec.push(ENCODING_VERSION);

        // keys
        encoded_vec
            .extend_from_slice(CompressedRistrettoPublic::from(self.view_public_key()).as_ref());
        encoded_vec
            .extend_from_slice(CompressedRistrettoPublic::from(self.spend_public_key()).as_ref());

        // Fog url
        if let Some(fog_url) = self.fog_url() {
            encoded_vec.push(fog_url.len() as u8);
            encoded_vec.extend_from_slice(&fog_url.as_bytes());
        }

        // Prepend with checksum
        let mut checksum_vec = Vec::new();
        checksum_vec.extend_from_slice(&checksum(&encoded_vec)[..]);
        checksum_vec.extend_from_slice(&encoded_vec);
        bs58::encode(&checksum_vec[..]).into_string()
    }
}

#[cfg(test)]
mod testing {
    use super::*;
    use crate::account_keys::AccountKey;
    #[test]
    fn public_address_encoding_roundtrip() {
        test_helper::run_with_several_seeds(|mut rng| {
            {
                let acct = AccountKey::random(&mut rng);
                let encoded = acct.default_subaddress().encode();
                let result = PublicAddress::decode(encoded).unwrap();
                assert_eq!(acct.default_subaddress(), result);
            }
            {
                let acct = AccountKey::random_with_fog(&mut rng);
                let encoded = acct.default_subaddress().encode();
                let result = PublicAddress::decode(encoded).unwrap();
                assert_eq!(acct.default_subaddress(), result);
            }
        });
    }
    #[test]
    fn sample_public_addresses() {
        // These are the test cases used in other libraries, they should be consistent
        // regardless of implementation
        let alice_view = [
            166, 74, 193, 46, 6, 55, 219, 137, 34, 216, 57, 161, 74, 3, 239, 221, 4, 18, 227, 206,
            47, 97, 22, 65, 183, 227, 61, 51, 113, 56, 24, 25,
        ];
        let alice_spend = [
            150, 146, 51, 240, 178, 213, 250, 183, 11, 84, 216, 245, 95, 116, 41, 121, 176, 45, 39,
            240, 198, 218, 32, 224, 10, 178, 70, 194, 198, 211, 21, 52,
        ];
        let alice_public = PublicAddress::new_with_fog(
            &RistrettoPublic::try_from(&alice_spend).unwrap(),
            &RistrettoPublic::try_from(&alice_view).unwrap(),
            "example.com",
        );
        let alice_address = "ujop75aHu64WKZgYGEr4UJJZXk5j9jAUtnLdcdifcJ5nCrehWwEgNQZd3JLpLSV55WfUtsURxsghuoX8rpeLgF9xQZN4bDau3XztijShBMvtkqak";
        let alice_decoded = PublicAddress::decode(String::from(alice_address)).unwrap();
        assert_eq!(alice_public, alice_decoded);

        let bob_view = [
            74, 212, 31, 106, 179, 194, 87, 189, 2, 248, 103, 65, 73, 73, 97, 130, 224, 178, 164,
            95, 242, 176, 49, 182, 201, 137, 235, 243, 253, 165, 159, 119,
        ];
        let bob_spend = [
            98, 4, 17, 200, 238, 250, 195, 28, 250, 227, 124, 56, 234, 222, 169, 21, 114, 123, 133,
            205, 242, 36, 50, 213, 149, 136, 172, 233, 99, 151, 152, 114,
        ];
        let bob_public = PublicAddress::new_with_fog(
            &RistrettoPublic::try_from(&bob_spend).unwrap(),
            &RistrettoPublic::try_from(&bob_view).unwrap(),
            "example.com",
        );
        let bob_address = "wM1y2oMStbmRysFv1aABTFDjKT1zzfHzT8dDf1HGyigfduPmKj89CgAJhhnHTzAjuAU8ZN1Bv8S3qAWk6cW6piGsrP4sWRUuzrWCR4zqkAZ1C94g";
        let bob_decoded = PublicAddress::decode(String::from(bob_address)).unwrap();
        assert_eq!(bob_public, bob_decoded);
    }

    #[test]
    fn bad_public_address_encoding() {
        assert_eq!(
            PublicAddress::decode(String::from(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ))
            .unwrap_err(),
            AddressParseError::InsufficientBytes
        );
        assert_eq!(
            PublicAddress::decode(String::from(
                "0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o"
            ))
            .unwrap_err(),
            AddressParseError::Base58DecodingError
        );
        assert_eq!(
            PublicAddress::decode(String::from(
                "Ujop75aHu64WKZgYGEr4UJJZXk5j9jAUtnLdcdifcJ5nCrehWwEgNQZd3JLpLSV55WfUtsURxsghuoX8rpeLgF9xQZN4bDau3XztijShBMvtkqak"
            ))
            .unwrap_err(),
            AddressParseError::ChecksumError
        );
    }
}
