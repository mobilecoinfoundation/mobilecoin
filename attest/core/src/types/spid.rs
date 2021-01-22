// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This is the FFI wrapper type for sgx_keyid_t

use crate::{impl_hexstr_for_bytestruct, impl_sgx_newtype_for_bytestruct};
use core::str::FromStr;
use mc_sgx_types::sgx_spid_t;
use mc_util_encodings::FromHex;

const SIZE: usize = 16;

/// An SGX Service Provider ID
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct ProviderId(sgx_spid_t);

impl_sgx_newtype_for_bytestruct! {
    ProviderId, sgx_spid_t, SIZE, id;
}

impl_hexstr_for_bytestruct! {
    ProviderId, SIZE, id;
}

/// Convert from a string to a provider ID.
///
/// This forces the canonical string representation of a Service Provider ID to
/// hex, and is required for this type to be used in structopt configurations.
impl FromStr for ProviderId {
    type Err = <ProviderId as FromHex>::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_util_serial::{deserialize, serialize};

    #[test]
    fn test_serde() {
        let src = sgx_spid_t {
            id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        };

        let spid: ProviderId = src.into();
        let serialized = serialize(&spid).expect("Could not serialize cpu_spid");
        let spid2: ProviderId = deserialize(&serialized).expect("Could not deserialize cpu_spid");
        assert_eq!(spid, spid2);
    }
}
