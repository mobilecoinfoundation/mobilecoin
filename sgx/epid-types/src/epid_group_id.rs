// Copyright (c) 2018-2020 MobileCoin Inc.

//! SGX Quote wrapper

use core::{
    cmp::Ordering,
    convert::TryFrom,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use hex_fmt::HexFmt;
use mc_sgx_core_types::{impl_ffi_wrapper_base, impl_hex_base64_with_repr_bytes};
use mc_sgx_epid_types_sys::sgx_epid_group_id_t;
use mc_util_encodings::Error as EncodingError;
#[cfg(feature = "use_prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;
#[cfg(feature = "use_serde")]
use mc_util_repr_bytes::derive_serde_from_repr_bytes;
use mc_util_repr_bytes::{
    derive_into_vec_from_repr_bytes, derive_repr_bytes_from_as_ref_and_try_from, typenum::U4,
};
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
    EpidGroupId, sgx_epid_group_id_t;
}

derive_repr_bytes_from_as_ref_and_try_from!(EpidGroupId, U4);
derive_into_vec_from_repr_bytes!(EpidGroupId);
impl_hex_base64_with_repr_bytes!(EpidGroupId);

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(EpidGroupId);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(EpidGroupId);

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

impl PartialOrd for EpidGroupId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl TryFrom<&[u8]> for EpidGroupId {
    type Error = EncodingError;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        let mut retval = Self::default();
        if src.len() < EPID_GROUP_ID_SIZE {
            return Err(EncodingError::InvalidInputLength);
        }

        retval.0.copy_from_slice(&src[..EPID_GROUP_ID_SIZE]);
        Ok(retval)
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    #[cfg(feature = "use_serde")]
    use bincode::{deserialize, serialize};
    use std::format;

    #[cfg(feature = "use_serde")]
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
