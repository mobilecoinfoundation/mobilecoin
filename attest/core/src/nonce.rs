// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Nonce structures

use alloc::vec;

use crate::{error::NonceError, impl_sgx_newtype_for_bytestruct, traits::bin2hex};
use alloc::vec::Vec;
use binascii::hex2bin;
use core::{
    convert::{AsRef, Into, TryFrom, TryInto},
    fmt::{Display, Formatter, Result as FmtResult},
    write,
};
use hex_fmt::HexFmt;
use mc_crypto_rand::{CryptoRng, RngCore};
use mc_sgx_types::sgx_quote_nonce_t;
use mc_util_encodings::{Error as EncodingError, FromHex, ToHex};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

/// A trait used to define common operations on nonce values
pub trait Nonce:
    AsRef<[u8]>
    + PartialEq
    + Sized
    + for<'bytes> TryFrom<&'bytes [u8]>
    + TryFrom<Vec<u8>>
    + ConstantTimeEq
{
    /// Generate a new nonce from random data
    fn new<R: RngCore + CryptoRng>(csprng: &mut R) -> Result<Self, NonceError>
    where
        NonceError: From<<Self as TryFrom<Vec<u8>>>::Error>,
    {
        let mut bytevec: Vec<u8> = vec![0u8; Self::size()];
        csprng.fill_bytes(&mut bytevec);
        let result = bytevec.try_into()?;
        Ok(result)
    }

    /// Copy the contents of this nonce into a byte vector.
    fn to_vec(&self) -> Vec<u8> {
        let slice: &[u8] = self.as_ref();
        Vec::from(slice)
    }

    /// Retrieve the desired length of a nonce (should be at least 16 bytes).
    fn size() -> usize;

    /// Retrieve the length, in bytes, of a particular nonce instance.
    ///
    /// Nonce implementations with variable lengths should override this
    /// method to return the instance's true length.
    fn len(&self) -> usize {
        Self::size()
    }

    /// Determine whether the nonce value is empty or not.
    ///
    /// This method is, by default, going to test if len is zero.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The fixed length of an SGX quote nonce
const QUOTE_NONCE_LENGTH: usize = 16;

/// A structure wrapping a nonce to be used in an SGX quote
///
/// # Example
///
/// ```
/// use mc_attest_core::{Nonce, QuoteNonce};
/// use rand::prelude::*;
/// use rand_hc::Hc128Rng as FixedRng;
///
/// // chosen by fair dice roll, or: use a real rng in real code, folks.
/// let mut csprng: FixedRng = SeedableRng::seed_from_u64(0);
/// let nonce = QuoteNonce::new(&mut csprng).expect("Could not create nonce");
/// let nonce_contents: &[u8] = nonce.as_ref();
/// let expected = [226u8, 30, 184, 201, 207, 62, 43, 114, 89, 4, 220, 27, 84, 79, 238, 234];
/// assert_eq!(nonce_contents, &expected[..]);
/// ```
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct QuoteNonce(sgx_quote_nonce_t);

impl_sgx_newtype_for_bytestruct! {
    QuoteNonce, sgx_quote_nonce_t, QUOTE_NONCE_LENGTH, rand;
}

impl Nonce for QuoteNonce {
    fn size() -> usize {
        QUOTE_NONCE_LENGTH
    }
}

/// The fixed number of chars in the IAS nonce string is 32
/// In order to do the hex encoding, set the data length to 32/2,
/// since each byte is 2 chars.
const IAS_NONCE_LENGTH: usize = 16;
const IAS_NONCE_STR_LENGTH: usize = 2 * IAS_NONCE_LENGTH;

/// The IasNonce is provided with the json request payload to Intel Attestation
/// Services.
///
/// (IAS Spec Documentation)[https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf]
/// The documentation is slightly unclear as to what encoding should be used, so
/// the Nonce struct here assumes the data will be hex encoded.
#[derive(Clone, Debug, Default, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(transparent)]
pub struct IasNonce([u8; IAS_NONCE_LENGTH]);

impl AsRef<[u8]> for IasNonce {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl ConstantTimeEq for IasNonce {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Display for IasNonce {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", HexFmt(&self))
    }
}

impl FromHex for IasNonce {
    type Error = EncodingError;

    fn from_hex(s: &str) -> Result<Self, EncodingError> {
        if s.len() != IAS_NONCE_STR_LENGTH {
            return Err(EncodingError::InvalidInputLength);
        }
        let mut retval = Self::default();
        hex2bin(s.as_bytes(), &mut retval.0[..])?;
        Ok(retval)
    }
}

impl ToHex for IasNonce {
    fn to_hex(&self, dest: &mut [u8]) -> Result<usize, usize> {
        match bin2hex(self.as_ref(), dest) {
            Ok(buffer) => Ok(buffer.len()),
            Err(_e) => Err(IAS_NONCE_STR_LENGTH),
        }
    }
}

impl Nonce for IasNonce {
    fn size() -> usize {
        IAS_NONCE_LENGTH
    }
}

impl<'bytes> TryFrom<&'bytes [u8]> for IasNonce {
    type Error = EncodingError;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        if src.len() < IAS_NONCE_LENGTH {
            return Err(EncodingError::InvalidInputLength);
        }

        let mut retval = IasNonce([0u8; IAS_NONCE_LENGTH]);
        retval.0[..].copy_from_slice(&src[..IAS_NONCE_LENGTH]);
        Ok(retval)
    }
}

impl TryFrom<Vec<u8>> for IasNonce {
    type Error = EncodingError;

    fn try_from(src: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&src[..])
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use alloc::string::ToString;
    use rand::SeedableRng;
    use rand_hc::Hc128Rng as FixedRng;

    #[test]
    /// Test the output of the IasNonce to make sure it is a string compatible
    /// with IAS
    fn test_ias_nonce_len() {
        let mut seeded_rng: FixedRng = SeedableRng::from_seed([1u8; 32]);
        let ias_nonce = IasNonce::new(&mut seeded_rng).unwrap();
        assert_eq!(ias_nonce.len(), 16); // returned by Self.size()
        let hexed = hex::encode(ias_nonce.0);
        assert_eq!(ias_nonce.0.len(), 16);
        assert_eq!(hexed.chars().count(), 32);
    }

    #[test]
    /// Test hex encoding using data explicitly, and that it matches our
    /// to_string hex
    fn test_to_string_and_hex_encoding() {
        let mut seeded_rng: FixedRng = SeedableRng::from_seed([1u8; 32]);
        let ias_nonce = IasNonce::new(&mut seeded_rng).unwrap();
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
        let ias_nonce = IasNonce::from_hex(&s).unwrap();
        assert_eq!(
            [2, 154, 47, 57, 69, 168, 246, 187, 31, 181, 177, 26, 84, 40, 58, 64],
            ias_nonce.0
        );
        let decoded = hex::decode(&s).unwrap();
        assert_eq!(decoded, ias_nonce.0);
    }
}
