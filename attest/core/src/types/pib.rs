// Copyright (c) 2018-2021 The MobileCoin Foundation

//! FFI type for the sgx_platform_info_t

use alloc::vec;

use crate::impl_sgx_newtype_for_bytestruct;
use alloc::borrow::ToOwned;
use binascii::{b64decode, hex2bin};
use mc_sgx_types::{sgx_platform_info_t, SGX_PLATFORM_INFO_SIZE};
use mc_util_encodings::{Error as EncodingError, FromBase64, FromHex};

/// An opaque platform info blob structure.
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct PlatformInfoBlob(sgx_platform_info_t);

impl_sgx_newtype_for_bytestruct! {
    PlatformInfoBlob, sgx_platform_info_t, SGX_PLATFORM_INFO_SIZE, platform_info;
}

/// The base64 encoding of a PIB provided by Intel has a peculiar format---it
/// encodes an additional 4-byte prefix to the blob, which is not actually used
/// anywhere else.
//
// FIXME: move the IAS-provided PIB+4 format into it's own type, and provide
//        conversion to/from it instead.
impl FromBase64 for PlatformInfoBlob {
    type Error = EncodingError;

    fn from_base64(src: &str) -> Result<Self, EncodingError> {
        if src.len() % 4 != 0 {
            return Err(EncodingError::InvalidInputLength);
        }

        let expected_len = src.len() / 4 * 3;
        if expected_len < SGX_PLATFORM_INFO_SIZE {
            return Err(EncodingError::InvalidInputLength);
        }

        // This double-copy awfulness brought to you by Intel(tm) *jingle*
        let mut data = vec![0u8; src.len() / 4 * 3];
        let data_len = {
            let output = b64decode(src.as_bytes(), data.as_mut_slice())?;
            output.len()
        };
        data.truncate(data_len);
        let mut retval = Self::default();
        retval.0.platform_info[..].copy_from_slice(&data[4..(SGX_PLATFORM_INFO_SIZE + 4)]);
        Ok(retval)
    }
}

/// The hexadecimal encoding of a PIB provided by Intel has a peculiar
/// format---it encodes an additional 4-byte prefix to the blob, which is not
/// actually used anywhere else.
//
// FIXME: move the IAS-provided PIB+4 format into it's own type, and provide
//        conversion to/from it instead.
impl FromHex for PlatformInfoBlob {
    type Error = EncodingError;

    fn from_hex(src: &str) -> Result<Self, EncodingError> {
        const PIB_PREFIX_LEN: usize = 4;

        let owned_src = if src.len() % 2 != 0 {
            "0".to_owned() + src
        } else {
            src.to_owned()
        };

        let mut data = vec![0u8; SGX_PLATFORM_INFO_SIZE + PIB_PREFIX_LEN];
        hex2bin(owned_src.as_bytes(), data.as_mut_slice())?;

        let mut retval = Self::default();
        retval.0.platform_info[..].copy_from_slice(&data[PIB_PREFIX_LEN..]);
        Ok(retval)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_util_serial::{deserialize, serialize};

    #[test]
    fn test_serde() {
        let src = sgx_platform_info_t {
            platform_info: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
                45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
                66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
                87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101,
            ],
        };

        let pib: PlatformInfoBlob = src.into();
        let serialized = serialize(&pib).expect("Could not serialize pib");
        let pib2: PlatformInfoBlob = deserialize(&serialized).expect("Could not deserialize pib");
        assert_eq!(pib, pib2);
    }
}
