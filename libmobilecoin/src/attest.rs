// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{common::*, LibMcError};
use aes_gcm::Aes256Gcm;
use core::str::FromStr;
use libc::ssize_t;
use mc_attest_ake::{
    AuthPending, AuthResponseInput, AuthResponseOutput, ClientInitiate, Ready, Start, Transition,
};
use mc_attest_core::{
    MrEnclave, MrEnclaveVerifier, MrSigner, MrSignerVerifier, Verifier, DEBUG_ENCLAVE,
};
use mc_common::ResponderId;
use mc_crypto_keys::X25519;
use mc_crypto_noise::NoiseCipher;
use mc_crypto_rand::McRng;
use mc_util_ffi::*;
use sha2::Sha512;

pub type McMrEnclaveVerifier = MrEnclaveVerifier;
impl_into_ffi!(MrEnclaveVerifier);

#[no_mangle]
pub extern "C" fn mc_mr_enclave_verifier_free(
    mr_enclave_verifier: FfiOptOwnedPtr<McMrEnclaveVerifier>,
) {
    ffi_boundary(|| {
        let _ = mr_enclave_verifier;
    })
}

/// Create a new status verifier that will check for the existence of the
/// given MrEnclave.
///
/// # Preconditions
///
/// * `mr_enclave` - must be 32 bytes in length.
#[no_mangle]
pub extern "C" fn mc_mr_enclave_verifier_create(
    mr_enclave: FfiRefPtr<McBuffer>,
) -> FfiOptOwnedPtr<McMrEnclaveVerifier> {
    ffi_boundary(|| {
        let mr_enclave = MrEnclave::try_from_ffi(&mr_enclave).expect("mr_enclave is invalid");
        MrEnclaveVerifier::new(mr_enclave)
    })
}

/// Assume an enclave with the specified measurement does not need
/// BIOS configuration changes to address the provided advisory ID.
///
/// This method should only be used when advised by an enclave author.
///
/// # Preconditions
///
/// * `advisory_id` - must be a nul-terminated C string containing valid UTF-8.
#[no_mangle]
pub extern "C" fn mc_mr_enclave_verifier_allow_config_advisory(
    mr_enclave_verifier: FfiMutPtr<McMrEnclaveVerifier>,
    advisory_id: FfiStr,
) -> bool {
    ffi_boundary(|| {
        let advisory_id = <&str>::try_from_ffi(advisory_id).expect("advisory_id is invalid");
        mr_enclave_verifier
            .into_mut()
            .allow_config_advisory(advisory_id);
    })
}

/// Assume the given MrEnclave value has the appropriate software/build-time
/// hardening for the given advisory ID.
///
/// This method should only be used when advised by an enclave author.
///
/// # Preconditions
///
/// * `advisory_id` - must be a nul-terminated C string containing valid UTF-8.
#[no_mangle]
pub extern "C" fn mc_mr_enclave_verifier_allow_hardening_advisory(
    mr_enclave_verifier: FfiMutPtr<McMrEnclaveVerifier>,
    advisory_id: FfiStr,
) -> bool {
    ffi_boundary(|| {
        let advisory_id = <&str>::try_from_ffi(advisory_id).expect("advisory_id is invalid");
        mr_enclave_verifier
            .into_mut()
            .allow_hardening_advisory(advisory_id);
    })
}

pub type McMrSignerVerifier = MrSignerVerifier;
impl_into_ffi!(MrSignerVerifier);

#[no_mangle]
pub extern "C" fn mc_mr_signer_verifier_free(
    mr_signer_verifier: FfiOptOwnedPtr<McMrSignerVerifier>,
) {
    ffi_boundary(|| {
        let _ = mr_signer_verifier;
    })
}

/// Create a new status verifier that will check for the existence of the
/// given MrSigner.
///
/// # Preconditions
///
/// * `mr_signer` - must be 32 bytes in length.
#[no_mangle]
pub extern "C" fn mc_mr_signer_verifier_create(
    mr_signer: FfiRefPtr<McBuffer>,
    expected_product_id: u16,
    minimum_security_version: u16,
) -> FfiOptOwnedPtr<McMrSignerVerifier> {
    ffi_boundary(|| {
        let mr_signer = MrSigner::try_from_ffi(&mr_signer).expect("mr_signer is invalid");
        MrSignerVerifier::new(mr_signer, expected_product_id, minimum_security_version)
    })
}

/// Assume an enclave with the specified measurement does not need
/// BIOS configuration changes to address the provided advisory ID.
///
/// This method should only be used when advised by an enclave author.
///
/// # Preconditions
///
/// * `advisory_id` - must be a nul-terminated C string containing valid UTF-8.
#[no_mangle]
pub extern "C" fn mc_mr_signer_verifier_allow_config_advisory(
    mr_signer_verifier: FfiMutPtr<MrSignerVerifier>,
    advisory_id: FfiStr,
) -> bool {
    ffi_boundary(|| {
        let advisory_id = <&str>::try_from_ffi(advisory_id).expect("advisory_id is invalid");
        mr_signer_verifier
            .into_mut()
            .allow_config_advisory(advisory_id);
    })
}

/// Assume an enclave with the specified measurement has the appropriate
/// software/build-time hardening for the given advisory ID.
///
/// This method should only be used when advised by an enclave author.
///
/// # Preconditions
///
/// * `advisory_id` - must be a nul-terminated C string containing valid UTF-8.
#[no_mangle]
pub extern "C" fn mc_mr_signer_verifier_allow_hardening_advisory(
    mr_signer_verifier: FfiMutPtr<MrSignerVerifier>,
    advisory_id: FfiStr,
) -> bool {
    ffi_boundary(|| {
        let advisory_id = <&str>::try_from_ffi(advisory_id).expect("advisory_id is invalid");
        mr_signer_verifier
            .into_mut()
            .allow_hardening_advisory(advisory_id);
    })
}

pub type McVerifier = Verifier;
impl_into_ffi!(Verifier);

/// Construct a new builder using the baked-in IAS root certificates and debug
/// settings.
#[no_mangle]
pub extern "C" fn mc_verifier_create() -> FfiOptOwnedPtr<McVerifier> {
    ffi_boundary(|| {
        let mut verifier = Verifier::default();
        verifier.debug(DEBUG_ENCLAVE);
        verifier
    })
}

#[no_mangle]
pub extern "C" fn mc_verifier_free(verifier: FfiOptOwnedPtr<McVerifier>) {
    ffi_boundary(|| {
        let _ = verifier;
    })
}

/// Verify the given MrEnclave-based status verifier succeeds
#[no_mangle]
pub extern "C" fn mc_verifier_add_mr_enclave(
    verifier: FfiMutPtr<McVerifier>,
    mr_enclave_verifier: FfiRefPtr<McMrEnclaveVerifier>,
) -> bool {
    ffi_boundary(|| {
        verifier
            .into_mut()
            .mr_enclave((*mr_enclave_verifier).clone());
    })
}

/// Verify the given MrSigner-based status verifier succeeds
#[no_mangle]
pub extern "C" fn mc_verifier_add_mr_signer(
    verifier: FfiMutPtr<McVerifier>,
    mr_signer_verifier: FfiRefPtr<McMrSignerVerifier>,
) -> bool {
    ffi_boundary(|| {
        verifier.into_mut().mr_signer((*mr_signer_verifier).clone());
    })
}

pub enum AttestAke {
    NotAttested,
    AuthPending(AuthPending<X25519, Aes256Gcm, Sha512>),
    Attested(Ready<Aes256Gcm>),
}

impl AttestAke {
    pub fn new() -> Self {
        Self::NotAttested
    }

    pub fn is_attested(&self) -> bool {
        matches!(self, Self::Attested(_))
    }

    pub fn take_auth_pending(&mut self) -> Option<AuthPending<X25519, Aes256Gcm, Sha512>> {
        if let Self::AuthPending(_) = self {
            let state = std::mem::replace(self, Self::NotAttested);
            if let Self::AuthPending(auth_pending) = state {
                return Some(auth_pending);
            }
        }
        None
    }

    pub fn attest_cipher(&self) -> Option<&Ready<Aes256Gcm>> {
        match self {
            Self::Attested(attest_cipher) => Some(attest_cipher),
            _ => None,
        }
    }

    pub fn attest_cipher_mut(&mut self) -> Option<&mut Ready<Aes256Gcm>> {
        match self {
            Self::Attested(attest_cipher) => Some(attest_cipher),
            _ => None,
        }
    }
}

impl Default for AttestAke {
    fn default() -> Self {
        Self::new()
    }
}

pub type McAttestAke = AttestAke;
impl_into_ffi!(AttestAke);

#[no_mangle]
pub extern "C" fn mc_attest_ake_create() -> FfiOptOwnedPtr<McAttestAke> {
    ffi_boundary(AttestAke::new)
}

#[no_mangle]
pub extern "C" fn mc_attest_ake_free(attest_ake: FfiOptOwnedPtr<McAttestAke>) {
    ffi_boundary(|| {
        let _ = attest_ake;
    })
}

#[no_mangle]
pub extern "C" fn mc_attest_ake_is_attested(
    attest_ake: FfiRefPtr<McAttestAke>,
    out_attested: FfiMutPtr<bool>,
) -> bool {
    ffi_boundary(|| *out_attested.into_mut() = attest_ake.is_attested())
}

/// # Preconditions
///
/// * `attest_ake` - must be in the attested state.
/// * `out_binding` - must be null or else length must be >= `binding.len`.
#[no_mangle]
pub extern "C" fn mc_attest_ake_get_binding(
    attest_ake: FfiRefPtr<McAttestAke>,
    out_binding: FfiOptMutPtr<McMutableBuffer>,
) -> ssize_t {
    ffi_boundary(|| {
        let attest_cipher = attest_ake
            .attest_cipher()
            .expect("attest_ake is not in the attested state");

        let binding = attest_cipher.binding();

        if let Some(out_binding) = out_binding.into_option() {
            out_binding
                .into_mut()
                .as_slice_mut_of_len(binding.len())
                .expect("out_binding length is insufficient")
                .copy_from_slice(binding);
        }
        ssize_t::ffi_try_from(binding.len()).expect("binding.len could not be converted to ssize_t")
    })
}

/// # Preconditions
///
/// * `responder_id` - must be a nul-terminated C string containing a valid
///   responder ID.
/// * `out_auth_request` - must be null or else length must be >=
///   auth_request_output.len.
#[no_mangle]
pub extern "C" fn mc_attest_ake_get_auth_request(
    attest_ake: FfiMutPtr<McAttestAke>,
    responder_id: FfiStr,
    rng_callback: FfiOptMutPtr<McRngCallback>,
    out_auth_request: FfiOptMutPtr<McMutableBuffer>,
) -> ssize_t {
    ffi_boundary(|| {
        let responder_id =
            ResponderId::try_from_ffi(responder_id).expect("responder_id is invalid");
        let mut rng = SdkRng::from_ffi(rng_callback);

        let start = Start::new(responder_id.to_string());
        let init_input = ClientInitiate::<X25519, Aes256Gcm, Sha512>::default();
        let (auth_pending, auth_request_output) = start
            .try_next(&mut rng, init_input)
            .expect("Ake start transition is no fail");
        *attest_ake.into_mut() = AttestAke::AuthPending(auth_pending);

        let auth_request_output = auth_request_output.as_ref();
        if let Some(out_auth_request) = out_auth_request.into_option() {
            out_auth_request
                .into_mut()
                .as_slice_mut_of_len(auth_request_output.len())
                .expect("out_auth_request length is insufficient")
                .copy_from_slice(auth_request_output);
        }
        ssize_t::ffi_try_from(auth_request_output.len())
            .expect("auth_request_output.len could not be converted to ssize_t")
    })
}

/// # Preconditions
///
/// * `attest_ake` - must be in the auth pending state.
///
/// # Errors
///
/// * `LibMcError::AttestationVerificationFailed`
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_attest_ake_process_auth_response(
    attest_ake: FfiMutPtr<McAttestAke>,
    auth_response_data: FfiRefPtr<McBuffer>,
    verifier: FfiRefPtr<McVerifier>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let attest_ake = attest_ake.into_mut();
        let auth_pending = attest_ake
            .take_auth_pending()
            .expect("attest_ake is not in the auth pending state");

        let auth_response_output = AuthResponseOutput::from(auth_response_data.to_vec());
        let auth_response_input = AuthResponseInput::new(auth_response_output, (*verifier).clone());
        let mut rng = McRng::default(); // This is actually unused.
        let (ready, _) = auth_pending.try_next(&mut rng, auth_response_input)?;
        *attest_ake = AttestAke::Attested(ready);

        Ok(())
    })
}

/// # Preconditions
///
/// * `attest_ake` - must be in the attested state.
/// * `out_ciphertext` - must be null or else length must be >=
///   `ciphertext.len`.
///
/// # Errors
///
/// * `LibMcError::Aead`
/// * `LibMcError::Cipher`
#[no_mangle]
pub extern "C" fn mc_attest_ake_encrypt(
    attest_ake: FfiMutPtr<McAttestAke>,
    aad: FfiRefPtr<McBuffer>,
    plaintext: FfiRefPtr<McBuffer>,
    out_ciphertext: FfiOptMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> ssize_t {
    ffi_boundary_with_error(out_error, || {
        let ciphertext_len = Aes256Gcm::ciphertext_len(plaintext.len());

        if let Some(out_ciphertext) = out_ciphertext.into_option() {
            let attest_cipher = attest_ake
                .into_mut()
                .attest_cipher_mut()
                .expect("attest_ake is not in the attested state");

            let ciphertext = attest_cipher.encrypt(aad.as_slice(), plaintext.as_slice())?;

            out_ciphertext
                .into_mut()
                .as_slice_mut_of_len(ciphertext_len)
                .expect("out_auth_request length is insufficient")
                .copy_from_slice(&ciphertext);
        }
        Ok(ssize_t::ffi_try_from(ciphertext_len)
            .expect("ciphertext.len could not be converted to ssize_t"))
    })
}

/// # Preconditions
///
/// * `attest_ake` - must be in the attested state.
/// * `out_plaintext` - length must be >= `ciphertext.len`.
///
/// # Errors
///
/// * `LibMcError::Aead`
/// * `LibMcError::Cipher`
#[no_mangle]
pub extern "C" fn mc_attest_ake_decrypt(
    attest_ake: FfiMutPtr<McAttestAke>,
    aad: FfiRefPtr<McBuffer>,
    ciphertext: FfiRefPtr<McBuffer>,
    out_plaintext: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> ssize_t {
    ffi_boundary_with_error(out_error, || {
        let attest_cipher = attest_ake
            .into_mut()
            .attest_cipher_mut()
            .expect("attest_ake is not in the attested state");

        let plaintext = attest_cipher.decrypt(aad.as_slice(), ciphertext.as_slice())?;

        out_plaintext
            .into_mut()
            .as_slice_mut_of_len(plaintext.len())
            .expect("out_plaintext length is insufficient")
            .copy_from_slice(&plaintext);
        Ok(ssize_t::ffi_try_from(plaintext.len())
            .expect("plaintext.len could not be converted to ssize_t"))
    })
}

impl<'a> TryFromFfi<&McBuffer<'a>> for MrEnclave {
    type Error = LibMcError;

    fn try_from_ffi(src: &McBuffer<'a>) -> Result<Self, LibMcError> {
        let src = <[u8; 32]>::try_from_ffi(src)?;
        Ok(MrEnclave::from(src))
    }
}

impl<'a> TryFromFfi<&McBuffer<'a>> for MrSigner {
    type Error = LibMcError;

    fn try_from_ffi(src: &McBuffer<'a>) -> Result<Self, LibMcError> {
        let src = <[u8; 32]>::try_from_ffi(src)?;
        Ok(MrSigner::from(src))
    }
}

impl<'a> TryFromFfi<FfiStr<'a>> for ResponderId {
    type Error = LibMcError;

    fn try_from_ffi(src: FfiStr<'a>) -> Result<Self, LibMcError> {
        let str = <&str>::try_from_ffi(src)?;
        ResponderId::from_str(str)
            .map_err(|err| LibMcError::InvalidInput(format!("Invalid responder id: {:?}", err)))
    }
}
