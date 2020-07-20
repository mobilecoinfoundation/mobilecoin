// Copyright (c) 2018-2020 MobileCoin Inc.

//! Nonce structures

use core::{
    convert::TryFrom,
    fmt::{Display, Formatter, Result as FmtResult},
};
use hex::{FromHex, FromHexError};
use hex_fmt::HexFmt;
use mc_util_from_random::FromRandom;
use mc_util_repr_bytes::typenum::U16;
use rand_core::{CryptoRng, RngCore};

const IAS_NONCE_SIZE: usize = 16;

/// The Nonce is provided with the JSON request payload to Intel Attestation
/// Services.
///
/// (IAS Spec Documentation)[https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf]
/// The documentation is slightly unclear as to what encoding should be used, so
/// the Nonce struct here assumes the data will be hex encoded.
#[derive(Clone, Debug, Default, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Nonce([u8; IAS_NONCE_SIZE]);

mc_util_repr_bytes::derive_repr_bytes_from_as_ref_and_try_from!(Nonce, U16);

#[cfg(feature = "use_prost")]
mc_util_repr_bytes::derive_prost_message_from_repr_bytes!(Nonce);

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Display for Nonce {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", HexFmt(&self))
    }
}

impl FromHex for Nonce {
    type Error = FromHexError;

    fn from_hex<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::Error> {
        let mut retval = Self::default();
        hex::decode_to_slice(src, &mut retval.0[..])?;
        Ok(retval)
    }
}

impl FromRandom for Nonce {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let mut retval = Self::default();
        csprng.fill_bytes(&mut retval.0[..]);
        retval
    }
}

impl<'bytes> TryFrom<&'bytes [u8]> for Nonce {
    type Error = usize;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        if src.len() != IAS_NONCE_SIZE {
            return Err(IAS_NONCE_SIZE);
        }

        let mut retval = Nonce::default();
        retval.0[..].copy_from_slice(&src[..IAS_NONCE_SIZE]);
        Ok(retval)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use alloc::string::ToString;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    #[test]
    /// Test hex encoding using data explicitly, and that it matches our
    /// to_string hex
    fn test_to_string_and_hex_encoding() {
        let mut seeded_rng = Hc128Rng::from_seed([1u8; 32]);
        let ias_nonce = Nonce::from_random(&mut seeded_rng);
        assert_eq!(
            [2, 154, 47, 57, 69, 168, 246, 187, 31, 181, 177, 26, 84, 40, 58, 64],
            ias_nonce.0
        );
        let nonce_to_string = ias_nonce.to_string();
        assert_eq!(
            "029a2f3945a8f6bb1fb5b11a54283a40".to_string(),
            nonce_to_string
        );
        let hexed_data = hex::encode(ias_nonce.0);
        assert_eq!("029a2f3945a8f6bb1fb5b11a54283a40".to_string(), hexed_data);
        let hexed_data_ref = hex::encode(ias_nonce.as_ref());
        assert_eq!(
            "029a2f3945a8f6bb1fb5b11a54283a40".to_string(),
            hexed_data_ref
        );
    }

    #[test]
    /// Test that our hex decoding matches hex::decode
    fn test_string_from_and_hex_decoding() {
        let s = "029a2f3945a8f6bb1fb5b11a54283a40";
        let ias_nonce = Nonce::from_hex(&s).unwrap();
        assert_eq!(
            [2, 154, 47, 57, 69, 168, 246, 187, 31, 181, 177, 26, 84, 40, 58, 64],
            ias_nonce.0
        );
        let decoded = hex::decode(&s).unwrap();
        assert_eq!(decoded, ias_nonce.0);
    }
}
