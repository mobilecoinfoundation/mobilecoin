//! Service Provider ID wrapper

use core::str::FromStr;
use mc_encodings::FromHex;
use mc_sgx_core_types::impl_ffi_wrapper;
use mc_sgx_epid_types_sys::sgx_spid_t;

/// The size of a [ProviderId]'s x64 representation, in bytes.
pub const PROVIDER_ID_SIZE: usize = 16;

/// A service provider ID, used to control access to IAS.
#[derive(Default)]
#[repr(transparent)]
pub struct ProviderId(sgx_spid_t);

impl_ffi_wrapper! {
    ProviderId, sgx_spid_t, PROVIDER_ID_SIZE, id;
}

/// Convert from a string to a provider ID.
///
/// This forces the canonical string representation of a Service Provider ID
/// to hex, and is required for this type to be used in structopt
/// configurations.
impl FromStr for ProviderId {
    type Err = <ProviderId as FromHex>::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bincode::{deserialize, serialize};

    #[test]
    fn serde() {
        let src = sgx_spid_t {
            id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        };

        let spid = ProviderId::from(src);
        let serialized = serialize(&spid).expect("Could not serialize spid");
        let spid2 = deserialize::<ProviderId>(&serialized).expect("Could not deserialize spid");
        assert_eq!(spid, spid2);
    }
}
