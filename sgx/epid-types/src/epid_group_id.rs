// Copyright (c) 2018-2020 MobileCoin Inc.

//! SGX Quote wrapper

use binascii::{b64decode, b64encode, bin2hex, hex2bin};
use core::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use hex_fmt::HexFmt;
use mc_sgx_core_types::impl_ffi_wrapper_base;
use mc_sgx_epid_types_sys::sgx_epid_group_id_t;
use mc_util_encodings::{
    base64_buffer_size, base64_size, Error as EncodingError, FromBase64, FromHex, FromX64,
    ToBase64, ToHex, ToX64,
};
use serde::{Serialize, Serializer};
use subtle::{Choice, ConstantTimeEq};

/// The size of an [EpidGroupId] x64 representation, in bytes.
pub const EPID_GROUP_ID_SIZE: usize = 4;

/// The EPID group ID structure, used to retrieve
#[derive(Default)]
#[repr(transparent)]
pub struct EpidGroupId(sgx_epid_group_id_t);

// We can't just use impl_ffi_wrapper because in spite of the fact it's declared as a [u8; 4], it is
// string-rendered as an LE u32. Yes, this is dumb.
impl_ffi_wrapper_base! {
    EpidGroupId, sgx_epid_group_id_t, EPID_GROUP_ID_SIZE;
}

impl AsRef<[u8]> for EpidGroupId {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsMut<[u8]> for EpidGroupId {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

impl ConstantTimeEq for EpidGroupId {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[..].ct_eq(&other.0[..])
    }
}

impl Debug for EpidGroupId {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "EpidGroupId: {}", HexFmt(&self))
    }
}

impl Display for EpidGroupId {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{:08x}", u32::from_le_bytes(self.0))
    }
}

impl From<&sgx_epid_group_id_t> for EpidGroupId {
    fn from(src: &sgx_epid_group_id_t) -> Self {
        let mut retval = Self::default();
        retval.0.copy_from_slice(&src[..]);
        retval
    }
}

impl FromBase64 for EpidGroupId {
    type Error = EncodingError;

    fn from_base64(s: &str) -> Result<Self, EncodingError> {
        if s.len() % 4 != 0 {
            return Err(EncodingError::InvalidInputLength);
        }

        // Don't try to decode any base64 string that's larger than our size limits or smaller
        // than our minimum size
        if s.len() != base64_size(EPID_GROUP_ID_SIZE) {
            return Err(EncodingError::InvalidInputLength);
        }

        // Create an output buffer of at least MINSIZE bytes
        let mut retval = Self::default();
        b64decode(s.as_bytes(), &mut retval.0[..])?;
        Ok(retval)
    }
}

impl FromHex for EpidGroupId {
    type Error = EncodingError;

    fn from_hex(s: &str) -> Result<Self, EncodingError> {
        if s.len() % 2 != 0 {
            return Err(EncodingError::InvalidInputLength);
        }

        if s.len() / 2 != EPID_GROUP_ID_SIZE {
            return Err(EncodingError::InvalidInputLength);
        }

        let mut retval = Self::default();
        hex2bin(s.as_bytes(), &mut retval.0[..])?;
        Ok(retval)
    }
}

impl<'src> FromX64 for EpidGroupId {
    type Error = EncodingError;

    fn from_x64(src: &[u8]) -> Result<Self, EncodingError> {
        if src.len() < EPID_GROUP_ID_SIZE {
            return Err(EncodingError::InvalidInputLength);
        }
        let mut retval = Self::default();
        retval.0[..].copy_from_slice(&src[..EPID_GROUP_ID_SIZE]);
        Ok(retval)
    }
}

impl Hash for EpidGroupId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "EpidGroupId".hash(state);
        (&self.0[..]).hash(state)
    }
}

impl Ord for EpidGroupId {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (&self.0[..]).cmp(&other.0[..])
    }
}

impl PartialEq for EpidGroupId {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Serialize for EpidGroupId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_newtype_struct("EpidGroupId", &self.0[..])
    }
}

impl ToBase64 for EpidGroupId {
    fn to_base64(&self, dest: &mut [u8]) -> Result<usize, usize> {
        let required_buffer_len = base64_buffer_size(EPID_GROUP_ID_SIZE);
        if dest.len() < required_buffer_len {
            Err(required_buffer_len)
        } else {
            match b64encode(&self.0[..], dest) {
                Ok(buffer) => Ok(buffer.len()),
                Err(_convert) => Err(required_buffer_len),
            }
        }
    }
}

impl ToHex for EpidGroupId {
    fn to_hex(&self, dest: &mut [u8]) -> Result<usize, usize> {
        match bin2hex(&self.0[..], dest) {
            Ok(buffer) => Ok(buffer.len()),
            Err(_e) => Err(EPID_GROUP_ID_SIZE * 2),
        }
    }
}

impl ToX64 for EpidGroupId {
    fn to_x64(&self, dest: &mut [u8]) -> Result<usize, usize> {
        if dest.len() < EPID_GROUP_ID_SIZE {
            return Err(EPID_GROUP_ID_SIZE);
        }
        dest[..EPID_GROUP_ID_SIZE].copy_from_slice(&self.0[..EPID_GROUP_ID_SIZE]);
        Ok(EPID_GROUP_ID_SIZE)
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use bincode::{deserialize, serialize};
    use std::format;

    #[test]
    fn serde() {
        let epid_gid = EpidGroupId::from([0u8, 1, 2, 3]);
        let ser = serialize(&epid_gid).expect("Error serializing epidgid.");
        let epid_gid2 = deserialize::<EpidGroupId>(&ser).expect("Error deserializing epidgid");
        assert_eq!(epid_gid, epid_gid2);
    }

    #[test]
    fn display() {
        let gid: sgx_epid_group_id_t = [0x2eu8, 0x0b, 0, 0];
        let epid_gid = EpidGroupId::from(gid);
        assert_eq!("00000b2e", format!("{}", epid_gid));
    }
}
