// Copyright (c) 2018-2020 MobileCoin Inc.

//! Nonce structures

use core::{
    convert::TryFrom,
    fmt::{Display, Formatter, Result as FmtResult},
};
use hex::{FromHex, ToHex};
use hex_fmt::HexFmt;
use mc_util_from_random::FromRandom;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const IAS_NONCE_SIZE: usize = 16;
const IAS_NONCE_STR_SIZE: usize = 2 * IAS_NONCE_SIZE;

/// The Nonce is provided with the JSON request payload to Intel Attestation Services.
///
/// (IAS Spec Documentation)[https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf]
/// The documentation is slightly unclear as to what encoding should be used, so
/// the Nonce struct here assumes the data will be hex encoded.

#[cfg_attr(not(feature = "prost"), derive(Debug, Default))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Clone, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Nonce([u8; IAS_NONCE_SIZE]);

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
    type Error = EncodingError;

    fn from_hex(s: &str) -> Result<Self, EncodingError> {
        if s.len() != IAS_NONCE_STR_SIZE {
            return Err(EncodingError::InvalidInputLength);
        }
        let mut retval = Self::default();
        hex2bin(s.as_bytes(), &mut retval.0[..])?;
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

impl ToHex for Nonce {
    fn to_hex(&self, dest: &mut [u8]) -> Result<usize, usize> {
        match bin2hex(self.as_ref(), dest) {
            Ok(buffer) => Ok(buffer.len()),
            Err(_e) => Err(IAS_NONCE_STR_SIZE),
        }
    }
}

impl<'bytes> TryFrom<&'bytes [u8]> for Nonce {
    type Error = EncodingError;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        if src.len() != IAS_NONCE_SIZE {
            return Err(EncodingError::InvalidInputLength);
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
    /// Test the output of the Nonce to make sure it is a string compatible with IAS
    fn test_ias_nonce_len() {
        let mut seeded_rng = Hc128Rng::from_seed([1u8; 32]);
        let ias_nonce = Nonce::from_random(&mut seeded_rng).unwrap();
        assert_eq!(ias_nonce.len(), 16); // returned by Self.size()
        let hexed = hex::encode(ias_nonce.0);
        assert_eq!(ias_nonce.0.len(), 16);
        assert_eq!(hexed.chars().count(), 32);
    }

    #[test]
    /// Test hex encoding using data explicitly, and that it matches our to_string hex
    fn test_to_string_and_hex_encoding() {
        let mut seeded_rng = Hc128Rng::from_seed([1u8; 32]);
        let ias_nonce = Nonce::from_random(&mut seeded_rng).unwrap();
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
