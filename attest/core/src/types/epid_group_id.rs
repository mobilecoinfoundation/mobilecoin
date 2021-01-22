// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains the wrapper type for an sgx_mac_t

use crate::{impl_sgx_wrapper_reqs, traits::SgxWrapperType};
use alloc::vec::Vec;
use core::{
    cmp::{Ord, Ordering},
    convert::TryFrom,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use mc_sgx_types::sgx_epid_group_id_t;
use mc_util_encodings::Error as EncodingError;

const EPID_GROUP_ID_SIZE: usize = 4;

/// A configuration ID data type
///
/// This type exists because of the lack of non-type polymorphism, and
/// should be removed once https://github.com/rust-lang/rust/issues/44580
/// has been completed.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct EpidGroupId(sgx_epid_group_id_t);

impl_sgx_wrapper_reqs! {
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

impl Default for EpidGroupId {
    fn default() -> Self {
        Self([0u8; 4])
    }
}

impl Debug for EpidGroupId {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        write!(formatter, "{}: {:?}", stringify!(EpidGroupId), &self.0[..])
    }
}

impl Display for EpidGroupId {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        write!(formatter, "{:08x}", u32::from_le_bytes(self.0))
    }
}

impl Hash for EpidGroupId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl Ord for EpidGroupId {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.0[..]).cmp(&other.0[..])
    }
}

impl PartialEq for EpidGroupId {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl SgxWrapperType<sgx_epid_group_id_t> for EpidGroupId {
    fn write_ffi_bytes(src: &sgx_epid_group_id_t, dest: &mut [u8]) -> Result<usize, EncodingError> {
        if dest.len() < 4 {
            return Err(EncodingError::InvalidOutputLength);
        }
        dest[..4].copy_from_slice(&src[..4]);
        Ok(4)
    }
}

impl<'src> TryFrom<&'src [u8]> for EpidGroupId {
    type Error = EncodingError;

    fn try_from(src: &[u8]) -> Result<Self, EncodingError> {
        if src.len() < 4 {
            return Err(EncodingError::InvalidInputLength);
        }
        let mut retval = Self::default();
        retval.0[..].copy_from_slice(&src[..4]);
        Ok(retval)
    }
}

impl TryFrom<Vec<u8>> for EpidGroupId {
    type Error = EncodingError;

    fn try_from(src: Vec<u8>) -> Result<Self, EncodingError> {
        if src.len() < 4 {
            return Err(EncodingError::InvalidInputLength);
        }
        let mut retval = Self::default();
        retval.0[..].copy_from_slice(&src[..4]);
        Ok(retval)
    }
}

impl From<u32> for EpidGroupId {
    fn from(src: u32) -> Self {
        let mut retval = Self::default();
        retval.0[0..4].copy_from_slice(&src.to_le_bytes());
        retval
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use std::format;

    use super::*;
    use core::convert::TryFrom;
    use mc_util_serial::*;

    #[test]
    fn test_serde() {
        let gid = [0u8, 1, 2, 3];
        let epid_gid =
            EpidGroupId::try_from(&gid[..]).expect("Could not create group ID from bytes.");

        let ser = serialize(&epid_gid).expect("Error serializing epidgid.");
        let epid_gid2: EpidGroupId = deserialize(&ser).expect("Error deserializing epidgid");
        assert_eq!(epid_gid, epid_gid2);
    }

    #[test]
    fn test_display() {
        let gid: sgx_epid_group_id_t = [0x2eu8, 0x0b, 0, 0];
        let epid_gid = EpidGroupId::from(gid);
        assert_eq!("00000b2e", format!("{}", epid_gid));
    }
}
