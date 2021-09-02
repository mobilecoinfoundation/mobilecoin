// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{common::*, LibMcError};
use core::convert::TryFrom;
use libc::ssize_t;
use mc_crypto_box::{generic_array::typenum::Unsigned, CryptoBox, VersionedCryptoBox};
use mc_crypto_keys::{ReprBytes, Ristretto, RistrettoPrivate, RistrettoPublic};
use mc_crypto_sig::{Signature, SIGNATURE_LENGTH};
use mc_util_ffi::*;
use zeroize::Zeroize;

/* ==== Ristretto ==== */

impl<'a> TryFromFfi<&McBuffer<'a>> for RistrettoPublic {
    type Error = LibMcError;

    fn try_from_ffi(src: &McBuffer<'a>) -> Result<Self, LibMcError> {
        let src = <&[u8; 32]>::try_from_ffi(src)?;
        RistrettoPublic::try_from(src).map_err(|err| LibMcError::InvalidInput(format!("{:?}", err)))
    }
}

impl<'a> TryFromFfi<&McBuffer<'a>> for RistrettoPrivate {
    type Error = LibMcError;

    fn try_from_ffi(src: &McBuffer<'a>) -> Result<Self, LibMcError> {
        let src = <&[u8; 32]>::try_from_ffi(src)?;
        RistrettoPrivate::try_from(src)
            .map_err(|err| LibMcError::InvalidInput(format!("{:?}", err)))
    }
}

#[no_mangle]
pub extern "C" fn mc_ristretto_private_validate(
    ristretto_private: FfiRefPtr<McBuffer>,
    out_valid: FfiMutPtr<bool>,
) -> bool {
    ffi_boundary(|| {
        *out_valid.into_mut() = RistrettoPrivate::try_from_ffi(&ristretto_private).is_ok();
    })
}

/// # Preconditions
///
/// * `ristretto_private` - must be a valid 32-byte Ristretto-format scalar.
/// * `out_ristretto_public` - length must be >= 32.
#[no_mangle]
pub extern "C" fn mc_ristretto_public_from_ristretto_private(
    ristretto_private: FfiRefPtr<McBuffer>,
    out_ristretto_public: FfiMutPtr<McMutableBuffer>,
) -> bool {
    ffi_boundary(|| {
        let ristretto_private = RistrettoPrivate::try_from_ffi(&ristretto_private)
            .expect("ristretto_private is not a valid RistrettoPrivate");
        let out_ristretto_public = out_ristretto_public
            .into_mut()
            .as_slice_mut_of_len(RistrettoPublic::size())
            .expect("out_fog_public_key length is insufficient");

        out_ristretto_public.copy_from_slice(ristretto_private.as_ref());
    })
}

#[no_mangle]
pub extern "C" fn mc_ristretto_public_validate(
    ristretto_public: FfiRefPtr<McBuffer>,
    out_valid: FfiMutPtr<bool>,
) -> bool {
    ffi_boundary(|| {
        *out_valid.into_mut() = RistrettoPublic::try_from_ffi(&ristretto_public).is_ok();
    })
}

/* ==== schnorrkel ==== */

impl<'a> TryFromFfi<&McBuffer<'a>> for Signature {
    type Error = LibMcError;

    fn try_from_ffi(src: &McBuffer<'a>) -> Result<Self, LibMcError> {
        let src = src.as_slice_of_len(SIGNATURE_LENGTH)?;
        Signature::from_bytes(src).map_err(|err| LibMcError::InvalidInput(format!("{:?}", err)))
    }
}

/* ==== VersionedCryptoBox ==== */

/// # Preconditions
///
/// * `public_key` - must be a valid 32-byte compressed Ristretto point.
/// * `out_ciphertext` - must be null or else length must be >=
///   `ciphertext.len`.
///
/// # Errors
///
/// * `LibMcError::Aead`
#[no_mangle]
pub extern "C" fn mc_versioned_crypto_box_encrypt(
    public_key: FfiRefPtr<McBuffer>,
    plaintext: FfiRefPtr<McBuffer>,
    rng_callback: FfiOptMutPtr<McRngCallback>,
    out_ciphertext: FfiOptMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> ssize_t {
    ffi_boundary_with_error(out_error, || {
        if let Some(out_ciphertext) = out_ciphertext.into_option() {
            let public_key = RistrettoPublic::try_from_ffi(&public_key)
                .expect("public_key is not a valid RistrettoPublic");
            let mut rng = SdkRng::from_ffi(rng_callback);

            let ciphertext =
                VersionedCryptoBox::default().encrypt(&mut rng, &public_key, &plaintext)?;

            out_ciphertext
                .into_mut()
                .as_slice_mut_of_len(ciphertext.len())
                .expect("out_ciphertext length is insufficient")
                .copy_from_slice(&ciphertext);
            Ok(ssize_t::ffi_try_from(ciphertext.len())
                .expect("ciphertext.len could not be converted to ssize_t"))
        } else {
            Ok(ssize_t::ffi_try_from(
                plaintext.len() + <VersionedCryptoBox as CryptoBox<Ristretto>>::FooterSize::USIZE,
            )
            .expect("Estimated ciphertext length could not be converted to ssize_t"))
        }
    })
}

/// # Preconditions
///
/// * `private_key` - must be a valid 32-byte Ristretto-format scalar.
/// * `out_plaintext` - length must be >= `ciphertext.len`.
///
/// # Errors
///
/// * `LibMcError::Aead`
/// * `LibMcError::InvalidInput`
/// * `LibMcError::UnsupportedCryptoBoxVersion`
#[no_mangle]
pub extern "C" fn mc_versioned_crypto_box_decrypt(
    private_key: FfiRefPtr<McBuffer>,
    ciphertext: FfiRefPtr<McBuffer>,
    out_plaintext: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> ssize_t {
    ffi_boundary_with_error(out_error, || {
        let private_key = RistrettoPrivate::try_from_ffi(&private_key)
            .expect("private_key is not a valid RistrettoPrivate");

        let (success, mut plaintext) =
            VersionedCryptoBox::default().decrypt(&private_key, &ciphertext)?;
        if !bool::from(success) {
            plaintext.zeroize();
            return Err(LibMcError::Aead("MAC failed".to_owned()));
        }

        out_plaintext
            .into_mut()
            .as_slice_mut_of_len(plaintext.len())
            .expect("out_plaintext length is insufficient")
            .copy_from_slice(&plaintext);
        Ok(ssize_t::ffi_try_from(plaintext.len())
            .expect("plaintext.len could not be converted to ssize_t"))
    })
}
