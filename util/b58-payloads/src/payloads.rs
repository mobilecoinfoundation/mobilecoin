//! Payload encodings for use in QR codes and deep links.

use crate::error::Error;

use core::{convert::TryFrom, fmt};
use std::str::FromStr;

use crc::crc32;
use mc_account_keys::{AccountKey, PublicAddress, RootIdentity};
use mc_crypto_keys::{KeyError, RistrettoPublic};
use mc_util_uri::FogUri;

/// Type of payload standard encoding.
#[repr(u8)] // we don't expect to ever need more than 255 payload types
enum PayloadType {
    Request = 0,
    Transfer = 1,
    // Wallet = 2,
    // Envelope = 3,
    AddressRequest = 5,
}

/// A little-endian IEEE CRC32 checksum is prepended to payloads.
fn calculate_checksum(data: &[u8]) -> [u8; 4] {
    crc32::checksum_ieee(data).to_le_bytes()
}

/// Calculate the checksum, prepend it to the payload bytes, and return base 58
fn encode_payload(bytes: Vec<u8>) -> String {
    let mut bytes_vec = Vec::new();
    bytes_vec.extend_from_slice(&calculate_checksum(&bytes));
    bytes_vec.extend_from_slice(&bytes);
    bs58::encode(&bytes_vec[..]).into_string()
}

/// This function is similar to `std::collections::VecDeque::split_off`, but provides error
/// checking. Note that `Vec::split_off` has the opposite semantics: it returns the values after
/// the split rather than before, so it isn't as useful here.
fn checked_split_off(bytes: &mut Vec<u8>, at: usize, value_name: &str) -> Result<Vec<u8>, Error> {
    if bytes.len() < at {
        return Err(Error::TooFewBytes(value_name.to_owned()));
    }
    // value = bytes[0..at]
    // bytes = bytes[at.. ]
    let mut value: Vec<u8> = Vec::with_capacity(at);
    value.extend_from_slice(&bytes[0..at]);
    *bytes = bytes.iter().skip(at).cloned().collect();
    Ok(value)
}

/// Convert a base58 string to bytes, verify the checksum, and return as a buffer.
/// Returns the tuple (version, buffer_bytes).
fn decode_payload(
    encoded_string: &str,
    expected_type: PayloadType,
) -> Result<(u8, Vec<u8>), Error> {
    let mut buffer_bytes: Vec<u8> = bs58::decode(encoded_string).into_vec()?;

    let checksum = checked_split_off(&mut buffer_bytes, 4, "checksum")?;
    let expected_checksum = calculate_checksum(&buffer_bytes);
    if checksum != expected_checksum {
        return Err(Error::ChecksumError);
    }

    let type_bytes = checked_split_off(&mut buffer_bytes, 1, "type_bytes")?;
    let payload_type_u8 = type_bytes[0] as u8;
    if payload_type_u8 != expected_type as u8 {
        return Err(Error::TypeMismatch);
    }

    let version_bytes = checked_split_off(&mut buffer_bytes, 1, "version_bytes")?;
    let version = version_bytes[0] as u8;

    Ok((version, buffer_bytes.to_vec()))
}

/// Validate a fog_report_url
fn validate_fog_report_url(fog_report_url: &str) -> Result<(), Error> {
    if fog_report_url.len() > 255 {
        return Err(Error::TooManyBytes("fog_report_url".to_owned()));
    }
    // Empty fog url is okay, otherwise it must parse as FogUri
    // TODO: Reject uri's containing a path?
    if !fog_report_url.is_empty() {
        FogUri::from_str(fog_report_url).map_err(Error::FogUrlParsingError)?;
    }
    Ok(())
}

/// Validate a memo
/// TODO: improve test
fn validate_memo(memo: &str) -> Result<(), Error> {
    if memo.len() > 255 {
        return Err(Error::TooManyBytes("memo".to_owned()));
    }
    Ok(())
}

/// RequestPayload is provided to a sender by a recipient to ask for payment.
#[derive(PartialEq, Eq, Clone)]
pub struct RequestPayload {
    /// The payload encoding version.
    version: u8,

    /// The view public key.
    pub view_public_key: [u8; 32],

    /// The spend public key.
    pub spend_public_key: [u8; 32],

    /// UTF-8 encoded fog report service URL. (Version 1+)
    pub fog_report_url: String,

    /// The requested value in picoMOB. (Version 2+)
    pub value: u64,

    /// UTF-8 encoded memo message. (Version 3+)
    pub memo: String,

    /// Bytes of user's signature over fog authority key (Version 4+)
    pub fog_authority_fingerprint_sig: Vec<u8>,

    /// The key labeling fog reports for this public address (Version 4+)
    pub fog_report_id: String,
}

impl fmt::Debug for RequestPayload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "version:{}, vpk:{}, spk:{}, fog:{}, fog-sig:{}, fog-id:{} value:{}, memo:{}",
            self.version,
            hex_fmt::HexFmt(&self.view_public_key),
            hex_fmt::HexFmt(&self.spend_public_key),
            self.fog_report_url,
            hex_fmt::HexFmt(&self.fog_authority_fingerprint_sig),
            self.fog_report_id,
            self.value,
            self.memo
        )
    }
}

impl RequestPayload {
    /// Create a new RequestPayload from an encoded string
    pub fn decode(encoded_string: &str) -> Result<Self, Error> {
        let (version, mut buffer_bytes) = decode_payload(encoded_string, PayloadType::Request)?;

        let view_key_bytes = checked_split_off(&mut buffer_bytes, 32, "view_public_key_bytes")?;
        let mut view_key: [u8; 32] = [0u8; 32];
        view_key.copy_from_slice(&view_key_bytes);

        let spend_key_bytes = checked_split_off(&mut buffer_bytes, 32, "spend_public_key_bytes")?;
        let mut spend_key: [u8; 32] = [0u8; 32];
        spend_key.copy_from_slice(&spend_key_bytes);

        let mut payload = RequestPayload::new_v0(&view_key, &spend_key)?;
        payload.version = version;
        if payload.version >= 1 {
            let fog_report_url_size_byte =
                checked_split_off(&mut buffer_bytes, 1, "fog_report_url_size_byte")?;
            let fog_report_url_size = fog_report_url_size_byte[0] as usize;
            let fog_report_url_bytes = checked_split_off(
                &mut buffer_bytes,
                fog_report_url_size,
                "fog_report_url_bytes",
            )?;
            payload.fog_report_url = String::from_utf8(fog_report_url_bytes.to_vec())?;
            validate_fog_report_url(&payload.fog_report_url)?;
        }
        if payload.version >= 2 {
            let value_bytes = checked_split_off(&mut buffer_bytes, 8, "value_bytes")?;
            let mut u64_bytes = [0u8; 8];
            u64_bytes.copy_from_slice(&value_bytes);
            payload.value = u64::from_le_bytes(u64_bytes);
        }
        if payload.version >= 3 {
            let memo_size_byte = checked_split_off(&mut buffer_bytes, 1, "memo_size_byte")?;
            let memo_size: usize = memo_size_byte[0] as usize;
            let memo_bytes = checked_split_off(&mut buffer_bytes, memo_size, "memo_bytes")?;
            payload.memo = String::from_utf8(memo_bytes.to_vec())?;
            validate_memo(&payload.memo)?;
        }
        if payload.version >= 4 {
            let fog_authority_fingerprint_sig_size_byte =
                checked_split_off(&mut buffer_bytes, 1, "fog_sig_size_byte")?;
            let fog_authority_fingerprint_sig_size =
                fog_authority_fingerprint_sig_size_byte[0] as usize;
            payload.fog_authority_fingerprint_sig = checked_split_off(
                &mut buffer_bytes,
                fog_authority_fingerprint_sig_size,
                "fog_sig_bytes",
            )?;

            let fog_report_id_size_byte =
                checked_split_off(&mut buffer_bytes, 1, "fog_report_id_size_byte")?;
            let fog_report_id_size = fog_report_id_size_byte[0] as usize;
            let fog_report_id_bytes =
                checked_split_off(&mut buffer_bytes, fog_report_id_size, "fog_report_id_bytes")?;
            payload.fog_report_id = String::from_utf8(fog_report_id_bytes.to_vec())?;
        }
        // ignore possible future bytes
        Ok(payload)
    }

    /// Create a version 0 RequestPayload
    pub fn new_v0(view_key: &[u8; 32], spend_key: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self {
            version: 0,
            view_public_key: *view_key,
            spend_public_key: *spend_key,
            fog_report_url: "".to_owned(),
            value: 0,
            memo: "".to_owned(),
            fog_report_id: Default::default(),
            fog_authority_fingerprint_sig: Default::default(),
        })
    }

    /// Create a version 1 RequestPayload - this is deprecated because fog now requires a signature
    #[deprecated]
    pub fn new_v1(
        view_key: &[u8; 32],
        spend_key: &[u8; 32],
        fog_report_url: &str,
    ) -> Result<Self, Error> {
        let mut result = RequestPayload::new_v0(view_key, spend_key)?;
        validate_fog_report_url(fog_report_url)?;
        result.fog_report_url = fog_report_url.to_owned();
        result.version = 1;
        Ok(result)
    }

    /// Create a version 2 RequestPayload
    pub fn new_v2(
        view_key: &[u8; 32],
        spend_key: &[u8; 32],
        fog_report_url: &str,
        value: u64,
    ) -> Result<Self, Error> {
        let mut result = RequestPayload::new_v0(view_key, spend_key)?;
        validate_fog_report_url(fog_report_url)?;
        result.fog_report_url = fog_report_url.to_owned();
        result.value = value;
        result.version = 2;
        Ok(result)
    }

    /// Create a version 3 RequestPayload
    pub fn new_v3(
        view_key: &[u8; 32],
        spend_key: &[u8; 32],
        fog_report_url: &str,
        value: u64,
        memo: &str,
    ) -> Result<Self, Error> {
        let mut result = RequestPayload::new_v2(view_key, spend_key, fog_report_url, value)?;
        validate_memo(memo)?;
        result.memo = memo.to_owned();
        result.version = 3;
        Ok(result)
    }

    /// Create a version 4 RequestPayload
    pub fn new_v4(
        view_key: &[u8; 32],
        spend_key: &[u8; 32],
        fog_report_url: &str,
        value: u64,
        memo: &str,
        fog_report_id: &str,
        fog_authority_fingerprint_sig: &[u8],
    ) -> Result<Self, Error> {
        let mut result = RequestPayload::new_v3(view_key, spend_key, fog_report_url, value, memo)?;
        result.fog_report_id = fog_report_id.to_owned();
        result.fog_authority_fingerprint_sig = fog_authority_fingerprint_sig.to_vec();
        result.version = 4;
        Ok(result)
    }

    /// Encodes the RequestPayload to a base 58 string.
    /// [0..4]            checksum
    /// [4]               PayloadType::Request
    /// [5]               version (< 256)
    /// [6..38]           public view key bytes [0..32]
    /// [38..70]          public spend key bytes [0..32]
    /// [70]              length of fog_report_url (f < 256)
    /// [71..F=(71+f)]    fog_report_url as utf-8 encoded string (< 256 bytes)
    /// [F..F+8]          u64 picoMOB value requested
    /// [F+8]             length of memo (m < 256)
    /// [F+9..M=(F+9+m)]  memo as utf-8 encoded string (< 256 bytes)
    /// [FIXME]           length of fog_authority_fingerprint_sig
    /// [FIXME]           fog_authority_fingerprint_sig bytes (< 256 bytes)
    /// [FIXME]           length of fog_report_id
    /// [FIXME]           fog_report_id bytes (< 256 bytes)
    /// [M..]             future version data (ignored)
    pub fn encode(&self) -> String {
        let mut bytes_vec = Vec::new();
        // Note that the checksum can't be calculated until all the other bytes are collected,
        // and will be added in the call to `encode_payload` at the end of this function.
        bytes_vec.push(PayloadType::Request as u8);
        bytes_vec.push(self.version);
        bytes_vec.extend_from_slice(&self.view_public_key);
        bytes_vec.extend_from_slice(&self.spend_public_key);
        if self.version >= 1 {
            bytes_vec.push(self.fog_report_url.len() as u8);
            bytes_vec.extend_from_slice(&self.fog_report_url.as_bytes());
        }
        if self.version >= 2 {
            bytes_vec.extend_from_slice(&self.value.to_le_bytes());
        }
        if self.version >= 3 {
            bytes_vec.push(self.memo.len() as u8);
            bytes_vec.extend_from_slice(&self.memo.as_bytes());
        }
        if self.version >= 4 {
            bytes_vec.push(self.fog_authority_fingerprint_sig.len() as u8);
            bytes_vec.extend_from_slice(self.fog_authority_fingerprint_sig.as_ref());
            bytes_vec.push(self.fog_report_id.len() as u8);
            bytes_vec.extend_from_slice(self.fog_report_id.as_ref());
        }
        encode_payload(bytes_vec)
    }
}

/// Decodes a RequestPayload to an account_keys::PublicAddress
impl TryFrom<&RequestPayload> for PublicAddress {
    type Error = KeyError;
    fn try_from(src: &RequestPayload) -> Result<Self, KeyError> {
        let spend_key = RistrettoPublic::try_from(&src.spend_public_key)?;
        let view_key = RistrettoPublic::try_from(&src.view_public_key)?;

        Ok(if src.version == 0 {
            PublicAddress::new(&spend_key, &view_key)
        } else {
            PublicAddress::new_with_fog(
                &spend_key,
                &view_key,
                &src.fog_report_url,
                src.fog_report_id.clone(),
                src.fog_authority_fingerprint_sig.clone(),
            )
        })
    }
}

/// We can create a v0 or v4 RequestPayload directly from a PublicAddress
impl TryFrom<&PublicAddress> for RequestPayload {
    type Error = Error;
    fn try_from(src: &PublicAddress) -> Result<Self, <Self as TryFrom<&PublicAddress>>::Error> {
        let view_pub: [u8; 32] = src.view_public_key().to_bytes();
        let spend_pub: [u8; 32] = src.spend_public_key().to_bytes();
        let mut payload = RequestPayload::new_v0(&view_pub, &spend_pub)?;
        if let Some(fog_report_url_string) = src.fog_report_url() {
            payload.version = 4;
            payload.fog_report_url = fog_report_url_string.to_string();
            if let Some(sig) = src.fog_authority_fingerprint_sig() {
                payload.fog_authority_fingerprint_sig = sig.to_vec();
            }
            if let Some(id) = src.fog_report_id() {
                payload.fog_report_id = id.to_string();
            }
        }
        Ok(payload)
    }
}

/// TransferPayload is provided to the recipient of funds to allow them to construct a self
/// payment.
#[derive(PartialEq, Eq, Clone)]
pub struct TransferPayload {
    /// The payload version.
    version: u8,

    /// The 32 bytes of entropy used to generate the transfer account.
    pub entropy: [u8; 32],

    /// Information used to find a utxo in the ledger.
    pub utxo: [u8; 32],

    /// utf-8 encoded memo message. (Version 1+)
    pub memo: String,
}

impl TransferPayload {
    /// Creates a new TransferPayload from an encoded string.
    pub fn decode(encoded_string: &str) -> Result<Self, Error> {
        let (version, mut buffer_bytes) = decode_payload(encoded_string, PayloadType::Transfer)?;

        let entropy_bytes = checked_split_off(&mut buffer_bytes, 32, "entropy_bytes")?;
        let mut entropy: [u8; 32] = [0u8; 32];
        entropy.copy_from_slice(&entropy_bytes);

        let utxo_bytes = checked_split_off(&mut buffer_bytes, 32, "utxo_bytes")?;
        let mut utxo: [u8; 32] = [0u8; 32];
        utxo.copy_from_slice(&utxo_bytes);

        let mut payload = TransferPayload::new_v0(&entropy, &utxo)?;
        payload.version = version;
        if payload.version >= 1 {
            let memo_size_byte = checked_split_off(&mut buffer_bytes, 1, "memo_size_byte")?;
            let memo_size: usize = memo_size_byte[0] as usize;
            let memo_bytes = checked_split_off(&mut buffer_bytes, memo_size, "memo_bytes")?;
            payload.memo = String::from_utf8(memo_bytes.to_vec())?;
            validate_memo(&payload.memo)?;
        }
        // ignore possible future bytes
        Ok(payload)
    }

    pub fn new_v0(entropy: &[u8; 32], utxo: &[u8; 32]) -> Result<Self, Error> {
        Ok(TransferPayload {
            version: 0,
            entropy: *entropy,
            utxo: *utxo,
            memo: "".to_owned(),
        })
    }

    pub fn new_v1(entropy: &[u8; 32], utxo: &[u8; 32], memo: &str) -> Result<Self, Error> {
        let mut result = TransferPayload::new_v0(entropy, utxo)?;
        validate_memo(memo)?;
        result.memo = memo.to_owned();
        result.version = 1;
        Ok(result)
    }

    /// Encodes this TransferPayload to a string
    /// [0..4]            checksum
    /// [4]               PayloadType::Transfer
    /// [5]               version (< 256)
    /// [6..38]           seed entropy bytes [0..32]
    /// [38..70]          utxo identifier bytes [0..32]
    /// [70]              length of memo (m < 256)
    /// [71..M=(71+f)]    memo as utf-8 encoded string (< 256 bytes)
    /// [M..]             future version data (ignored)
    pub fn encode(&self) -> String {
        let mut bytes_vec = Vec::new();
        // Note that the checksum can't be calculated until all the other bytes are collected,
        // and will be added in the call to `encode_payload` at the end of this function.
        bytes_vec.push(PayloadType::Transfer as u8);
        bytes_vec.push(self.version);
        bytes_vec.extend_from_slice(&self.entropy);
        bytes_vec.extend_from_slice(&self.utxo);
        if self.version >= 1 {
            bytes_vec.push(self.memo.len() as u8);
            bytes_vec.extend_from_slice(&self.memo.as_bytes());
        }
        encode_payload(bytes_vec)
    }
}

impl fmt::Debug for TransferPayload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "version:{}, entropy:{}, utxo:{}, memo:{}",
            self.version,
            hex_fmt::HexFmt(self.entropy),
            hex_fmt::HexFmt(self.utxo),
            self.memo
        )
    }
}

/// Decodes a TransferPayload to an account_keys::AccountKey
impl From<&TransferPayload> for AccountKey {
    fn from(src: &TransferPayload) -> Self {
        // TODO: change algorithm to AccountIdentity when available
        let id = RootIdentity::from(&src.entropy);
        AccountKey::from(&id)
    }
}

/// AddressRequestPayload encodes a URL to which a user to send a public address
#[derive(PartialEq, Eq, Clone)]
pub struct AddressRequestPayload {
    /// The payload version.
    version: u8,

    /// utf-8 encoded url
    pub url: String,
}

impl AddressRequestPayload {
    /// Creates a new AddressRequestPayload from an encoded string.
    pub fn decode(encoded_string: &str) -> Result<Self, Error> {
        let (version, mut buffer_bytes) =
            decode_payload(encoded_string, PayloadType::AddressRequest)?;

        let url_size_byte = checked_split_off(&mut buffer_bytes, 1, "url_size_byte")?;
        let url_size: usize = url_size_byte[0] as usize;
        let url_bytes = checked_split_off(&mut buffer_bytes, url_size, "memo_bytes")?;

        let mut payload = AddressRequestPayload::new_v0(String::from_utf8(url_bytes.to_vec())?)?;
        payload.version = version;
        Ok(payload)
    }

    pub fn new_v0(url: String) -> Result<Self, Error> {
        Ok(AddressRequestPayload { version: 0, url })
    }

    /// Encodes this AddressRequestPayload to a string
    /// [0..4]            checksum
    /// [4]               PayloadType::AddressRequest
    /// [5]               version (< 256)
    /// [f]               length of URL
    /// [6..(6+f)]        URL to POST address to
    pub fn encode(&self) -> String {
        let mut bytes_vec = Vec::new();
        // Note that the checksum can't be calculated until all the other bytes are collected,
        // and will be added in the call to `encode_payload` at the end of this function.
        bytes_vec.push(PayloadType::AddressRequest as u8);
        bytes_vec.push(self.version);
        bytes_vec.push(self.url.len() as u8);
        bytes_vec.extend_from_slice(&self.url.as_bytes());
        encode_payload(bytes_vec)
    }
}

impl fmt::Debug for AddressRequestPayload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "version:{}, url:{}", self.version, self.url,)
    }
}

#[cfg(test)]
mod testing {
    use super::*;
    use mc_account_keys::{AccountKey, PublicAddress};
    use mc_common::logger::{log, test_with_logger, Logger};
    use mc_util_test_helper::RngCore;

    /// Test that random account keys are recovered after encoding into a payload string
    /// and subsequently decoding, with and without fog urls.
    #[test_with_logger]
    fn request_code_roundtrip(logger: Logger) {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            {
                let acct = AccountKey::random(&mut rng);
                let public_address = acct.default_subaddress();
                let view_key_bytes = public_address.view_public_key().to_bytes();
                let spend_key_bytes = public_address.spend_public_key().to_bytes();

                //log::info!(logger, "{:?}", hex_fmt::HexFmt(&view_key_bytes));
                //log::info!(logger, "{:?}", hex_fmt::HexFmt(&spend_key_bytes));

                let payload = RequestPayload::try_from(&public_address).unwrap();
                log::info!(logger, " payload  {:?}", payload);

                let encoded_string = payload.encode();
                log::info!(logger, "encoded {:?}", encoded_string);

                let roundtrip_payload = RequestPayload::decode(&encoded_string).unwrap();
                log::info!(logger, "recovered {:?}", roundtrip_payload);

                assert_eq!(view_key_bytes, roundtrip_payload.view_public_key);
                assert_eq!(spend_key_bytes, roundtrip_payload.spend_public_key);

                let roundtrip_address = PublicAddress::try_from(&roundtrip_payload).unwrap();
                assert_eq!(public_address, roundtrip_address);
            }
            {
                let acct = AccountKey::random_with_fog(&mut rng);
                let public_address = acct.default_subaddress();
                let view_key_bytes = public_address.view_public_key().to_bytes();
                let spend_key_bytes = public_address.spend_public_key().to_bytes();
                let fog_url_string;
                match public_address.fog_report_url() {
                    Some(fog_url) => {
                        fog_url_string = fog_url.to_string();
                    }
                    None => {
                        fog_url_string = "".to_owned();
                    }
                }

                let payload = RequestPayload::try_from(&public_address).unwrap();
                assert_eq!(view_key_bytes, payload.view_public_key);
                assert_eq!(spend_key_bytes, payload.spend_public_key);
                assert_eq!(fog_url_string, payload.fog_report_url);

                let encoded_string = payload.encode();
                let roundtrip_payload = RequestPayload::decode(&encoded_string).unwrap();
                assert_eq!(view_key_bytes, roundtrip_payload.view_public_key);
                assert_eq!(spend_key_bytes, roundtrip_payload.spend_public_key);
                assert_eq!(fog_url_string, roundtrip_payload.fog_report_url);

                let roundtrip_address = PublicAddress::try_from(&roundtrip_payload).unwrap();
                assert_eq!(public_address, roundtrip_address);
            }
        });
    }

    // Test that two particular known addresses are encoded into the desired payload strings.
    #[test_with_logger]
    fn sample_request_codes(_logger: Logger) {
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
        let alice_fog_url = "fog://example.com".to_owned();
        let alice_fog_sig = vec![9u8, 9u8, 9u8, 9u8];
        let alice_public = PublicAddress::new_with_fog(
            &RistrettoPublic::try_from(&alice_spend).unwrap(),
            &RistrettoPublic::try_from(&alice_view).unwrap(),
            alice_fog_url,
            "".to_string(),
            alice_fog_sig,
        );
        let alice_request_payload = RequestPayload::try_from(&alice_public).unwrap();
        let alice_b58_str = alice_request_payload.encode();
        assert_eq!(alice_b58_str, "5F24DBwfEGBN18LevLEt3wZHknBk1tSC32QfMzSoiPcMrJyErBqBiNQpfFWboY1DHAjwjkBf2qfUbGvjvcdJ6Uhp6qcZ1NChFutR2MpiyTkrKm7NhCrT6KjtDkQBxr7rw74oFzvh7rkrK");
        let alice_payload = RequestPayload::decode(&alice_b58_str).unwrap();
        let alice_decoded = PublicAddress::try_from(&alice_payload).unwrap();
        assert_eq!(alice_public, alice_decoded);

        //log::info!(logger, "{:?}",  alice_payload);

        let bob_view = [
            74, 212, 31, 106, 179, 194, 87, 189, 2, 248, 103, 65, 73, 73, 97, 130, 224, 178, 164,
            95, 242, 176, 49, 182, 201, 137, 235, 243, 253, 165, 159, 119,
        ];
        let bob_spend = [
            98, 4, 17, 200, 238, 250, 195, 28, 250, 227, 124, 56, 234, 222, 169, 21, 114, 123, 133,
            205, 242, 36, 50, 213, 149, 136, 172, 233, 99, 151, 152, 114,
        ];
        let bob_fog_url = "fog://example.com".to_owned();
        let bob_fog_sig = vec![6u8, 6u8, 6u8, 6u8];
        let bob_public = PublicAddress::new_with_fog(
            &RistrettoPublic::try_from(&bob_spend).unwrap(),
            &RistrettoPublic::try_from(&bob_view).unwrap(),
            bob_fog_url,
            99.to_string(),
            bob_fog_sig,
        );
        let bob_request_payload = RequestPayload::try_from(&bob_public).unwrap();
        let bob_b58_str = bob_request_payload.encode();
        assert_eq!(bob_b58_str, "22M3RU5KkQ5izkdPhjAmj6KWs2Md3AuJTfeg7NxoJRyMsmiwV2NpdkA9ABrQSrHZuiEyHMJ4zxVwAeFDbjAHwx42AoFoLbYRkv19nwWFPLihthriKxCmvYpgVrzUpSbz27U1ASRhspZcqavc");
        let bob_payload = RequestPayload::decode(&bob_b58_str).unwrap();
        let bob_decoded = PublicAddress::try_from(&bob_payload).unwrap();
        assert_eq!(bob_public, bob_decoded);

        // Try Bob without fog
        let bob_public = PublicAddress::new(
            &RistrettoPublic::try_from(&bob_spend).unwrap(),
            &RistrettoPublic::try_from(&bob_view).unwrap(),
        );
        let bob_request_payload = RequestPayload::try_from(&bob_public).unwrap();
        let bob_b58_str = bob_request_payload.encode();
        assert_eq!(bob_b58_str, "72wW29sWRpkXtzuMhrcr5zjM3wvWDQj2FGCZf4eswvAhFMtCxdQjEYYmJfXtdTa7fLxGyELd6TT62Zb6nw6Hk7TfaX8nBAid");
        let bob_payload = RequestPayload::decode(&bob_b58_str).unwrap();
        let bob_decoded = PublicAddress::try_from(&bob_payload).unwrap();
        assert_eq!(bob_public, bob_decoded);
    }

    // Test that strings that can't be decoded generate the desired errors.
    #[test]
    fn bad_request_codes() {
        let mut bad_encoding = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            RequestPayload::decode(bad_encoding).unwrap_err(),
            Error::ChecksumError
        );

        bad_encoding = "0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o";
        assert_eq!(
            RequestPayload::decode(bad_encoding).unwrap_err(),
            Error::Base58DecodingError
        );

        bad_encoding = "Ujop75aHu64WKZgYGEr4UJJZXk5j9jAUtnLdcdifcJ5nCrehWwEgNQZd3JLpLSV55WfUtsURxsghuoX8rpeLgF9xQZN4bDau3XztijShBMvtkqak";
        assert_eq!(
            RequestPayload::decode(bad_encoding).unwrap_err(),
            Error::ChecksumError
        );
    }

    /// Test that random values recovered after encoding into a payload string
    /// and subsequently decoding, with and without a memo
    #[test_with_logger]
    fn transfer_code_roundtrip(logger: Logger) {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            {
                let mut entropy = [0u8; 32];
                rng.fill_bytes(&mut entropy);
                let mut utxo = [0u8; 32];
                rng.fill_bytes(&mut utxo);

                let payload = TransferPayload::new_v0(&entropy, &utxo).unwrap();
                log::info!(logger, " payload  {:?}", payload);

                let encoded_string = payload.encode();
                log::info!(logger, "encoded {:?}", encoded_string);

                let roundtrip_payload = TransferPayload::decode(&encoded_string).unwrap();
                log::info!(logger, "recovered {:?}", roundtrip_payload);

                assert_eq!(entropy, roundtrip_payload.entropy);
                assert_eq!(utxo, roundtrip_payload.utxo);

                let _account_key = AccountKey::from(&payload);
            }
            {
                let mut entropy = [0u8; 32];
                rng.fill_bytes(&mut entropy);
                let mut utxo = [0u8; 32];
                rng.fill_bytes(&mut utxo);
                let memo = "invoice 2349873978 🪔🌋";

                let payload = TransferPayload::new_v1(&entropy, &utxo, memo).unwrap();
                assert_eq!(entropy, payload.entropy);
                assert_eq!(utxo, payload.utxo);
                assert_eq!(memo, payload.memo);

                let encoded_string = payload.encode();
                let roundtrip_payload = TransferPayload::decode(&encoded_string).unwrap();
                assert_eq!(entropy, roundtrip_payload.entropy);
                assert_eq!(utxo, roundtrip_payload.utxo);
                assert_eq!(memo, roundtrip_payload.memo);

                let _account_key = AccountKey::from(&payload);
            }
        });
    }

    /// Test that Address Requests successfully encode and decode
    #[test_with_logger]
    fn address_request_roundtrip(logger: Logger) {
        let url = "https://example.com/address-endpoint/8473212-2812349".to_string();

        let payload = AddressRequestPayload::new_v0(url.clone()).unwrap();
        log::info!(logger, " payload  {:?}", payload);

        let encoded_string = payload.encode();
        log::info!(logger, "encoded {:?}", encoded_string);

        let roundtrip_payload = AddressRequestPayload::decode(&encoded_string).unwrap();
        log::info!(logger, "recovered {:?}", roundtrip_payload);

        assert_eq!(url, roundtrip_payload.url);
    }
}
