use alloc::vec::Vec;

use aead::{
    generic_array::{
        sequence::{Concat, Split},
        typenum::{Diff, Sum, Unsigned},
        ArrayLength, GenericArray,
    },
    Error as AeadError,
};
use core::ops::{Add, Sub};
use failure::Fail;
use mc_crypto_keys::{Kex, KeyError};
use rand_core::{CryptoRng, RngCore};

/// Error type for decryption
#[derive(PartialEq, Eq, Fail, Debug)]
pub enum Error {
    #[fail(display = "Error decoding curvepoint: {}", _0)]
    Key(KeyError),
    #[fail(
        display = "Too short, ciphertext is shorter than a footer: {} < {}",
        _0, _1
    )]
    TooShort(usize, usize),
    #[fail(display = "Mac failed")]
    MacFailed,
    #[fail(display = "Unknown algorithm code: {}", _0)]
    UnknownAlgorithm(usize),
    #[fail(display = "Wrong magic bytes")]
    WrongMagicBytes,
}

/// Trait defining the high-level interface to Crypto-Box
pub trait CryptoBox<KexAlgo: Kex>: Default {
    type FooterSize: ArrayLength<u8>;

    // Required functions

    /// Encrypt a buffer in place against a public key, and return the footer
    /// Fails only if the underlying AEAD fails
    ///
    /// Meant to mirror aead::encrypt_in_place_detached
    fn encrypt_in_place_detached<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        key: &KexAlgo::Public,
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::FooterSize>, AeadError>;

    /// Decrypt a buffer in place given the private key, and given the footer also
    ///
    /// Meant to mirror aead::decrypt_in_place_detached
    ///
    /// NOTE: Meant to run in constant-time even if the mac-check fails.
    ///
    /// Returns
    /// `Ok(true)` if decryption succeeds. `buffer` contains the plaintext and SHOULD be zeroized after use.
    /// `Ok(false) if MAC check fails. `buffer` contains failed plaintext and SHOULD be zeroized after use.
    fn decrypt_in_place_detached(
        &self,
        key: &KexAlgo::Private,
        footer: &GenericArray<u8, Self::FooterSize>,
        buffer: &mut [u8],
    ) -> Result<bool, Error>;

    // Provided functions
    // These functions consume and produce "cryptograms" where the footer bytes
    // are placed after the ciphertext bytes on the wire.

    /// Encrypt contents of a slice, returning the cryptogram in a Vec<u8>
    ///
    /// Meant to mirror aead::encrypt
    fn encrypt<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        key: &KexAlgo::Public,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let mut result = Vec::<u8>::with_capacity(plaintext.len() + Self::FooterSize::USIZE);
        result.extend_from_slice(plaintext);
        self.encrypt_in_place(rng, key, &mut result)?;
        Ok(result)
    }

    /// Decrypt a slice pointing to the cryptogram, returning a status and a Vec<u8> plaintext.
    /// If status is false then mac check failed and plaintext should be zeroed.
    ///
    /// Meant to mirror aead::decrypt
    fn decrypt(&self, key: &KexAlgo::Private, cryptogram: &[u8]) -> Result<(bool, Vec<u8>), Error> {
        let mut result = cryptogram.to_vec();
        let status = self.decrypt_in_place(key, &mut result)?;
        Ok((status, result))
    }

    /// Encrypt a buffer, extending the buffer to place the footer at the end.
    ///
    /// Meant to mirror aead::encrypt_in_place
    ///
    /// Fails if the underlying AEAD fails.
    fn encrypt_in_place<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        key: &KexAlgo::Public,
        buffer: &mut impl aead::Buffer,
    ) -> Result<(), AeadError> {
        let footer = self.encrypt_in_place_detached(rng, key, buffer.as_mut())?;
        buffer.extend_from_slice(&footer)
    }

    /// Counterpart to encrypt_in_place, which finds the footer at the end of
    /// the cryptogram.
    ///
    /// Meant to mirror aead::decrypt_in_place
    ///
    /// Decryption can fail if:
    /// - The buffer is too short to be interpretted
    /// - The curvepoint cannot be deserialized
    /// - The mac check fails
    ///
    /// Returns:
    /// - true if decryption succeeded, buffer contains plaintext
    /// - false if mac check failed, buffer contains failed plaintext.
    ///   Buffer SHOULD be zeroized to avoid attacks
    /// - error if anything else is wrong
    fn decrypt_in_place(
        &self,
        key: &KexAlgo::Private,
        cryptogram: &mut impl aead::Buffer,
    ) -> Result<bool, Error> {
        // Extract the footer from end of ciphertext, doing bounds checks
        if cryptogram.len() < Self::FooterSize::USIZE {
            return Err(Error::TooShort(cryptogram.len(), Self::FooterSize::USIZE));
        }
        let footer_pos = cryptogram.len() - Self::FooterSize::USIZE;
        let (ciphertext, footer) = cryptogram.as_mut().split_at_mut(footer_pos);
        // Note: this is modifying the cryptogram via the mutable slice ciphertext
        let status =
            self.decrypt_in_place_detached(key, GenericArray::from_slice(footer), ciphertext)?;
        cryptogram.truncate(footer_pos);
        Ok(status)
    }

    /// Encrypt a fixed-length buffer, producing a fixed-length buffer containing
    /// the cryptogram.
    ///
    /// A non-allocating counterpart to encrypt
    fn encrypt_fixed_length<T, L>(
        &self,
        rng: &mut T,
        key: &KexAlgo::Public,
        buffer: &GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, Sum<L, Self::FooterSize>>, AeadError>
    where
        T: RngCore + CryptoRng,
        L: ArrayLength<u8> + Add<Self::FooterSize>,
        Sum<L, Self::FooterSize>: ArrayLength<u8>,
    {
        let mut buffer = buffer.clone();
        let footer = self.encrypt_in_place_detached(rng, key, buffer.as_mut_slice())?;
        Ok(buffer.concat(footer))
    }

    /// Decrypt a cryptogram stored in a fixed-length buffer, producing
    /// the plaintext in a fixed-length buffer.
    ///
    /// A non-allocating counterpart to decrypt
    ///
    /// Returns:
    /// - true if decryption succeeded, buffer contains plaintext
    /// - false if mac check failed, buffer contains failed plaintext.
    ///   Buffer SHOULD be zeroized to avoid attacks
    /// - error if anything else is wrong
    fn decrypt_fixed_length<L>(
        &self,
        key: &KexAlgo::Private,
        cryptogram: &GenericArray<u8, L>,
    ) -> Result<(bool, GenericArray<u8, Diff<L, Self::FooterSize>>), Error>
    where
        L: ArrayLength<u8>
            + Sub<Self::FooterSize>
            + Sub<Diff<L, Self::FooterSize>, Output = Self::FooterSize>,
        Diff<L, Self::FooterSize>: ArrayLength<u8>,
    {
        let (mut ciphertext, footer) =
            Split::<u8, Diff<L, Self::FooterSize>>::split(cryptogram.clone());
        let status = self.decrypt_in_place_detached(key, &footer, ciphertext.as_mut_slice())?;
        Ok((status, ciphertext))
    }
}
