// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Common transitions and verification functions for initiators and responders.

use crate::{
    error::Error,
    event::{Ciphertext, NonceCiphertext, NoncePlaintext, Plaintext},
    mealy::Transition,
    state::Ready,
};
use alloc::{string::ToString, vec::Vec};
use der::DateTime;
use mc_attest_verifier::{DcapVerifier, Error as VerifierError};
use mc_attest_verifier_types::DcapEvidence;
use mc_attestation_verifier::{Evidence, TrustedIdentity, VerificationTreeDisplay};
use mc_crypto_keys::{KexPublic, ReprBytes};
use mc_crypto_noise::{CipherError, NoiseCipher};
use rand_core::CryptoRng;

/// Verify DCAP evidence and bind it to the remote identity authenticated by the
/// Noise handshake.
pub(crate) fn verify_dcap_evidence<PubKey: KexPublic>(
    dcap_evidence: DcapEvidence,
    identities: &[TrustedIdentity],
    time: Option<DateTime>,
    remote_identity: &PubKey,
) -> Result<(), Error> {
    let DcapEvidence {
        quote,
        collateral,
        report_data,
    } = dcap_evidence;

    if remote_identity.map_bytes(|bytes| bytes != report_data.key().to_bytes().as_slice()) {
        return Err(Error::BadRemoteIdentity);
    }

    let verifier = DcapVerifier::new(identities, time, report_data);
    let evidence =
        Evidence::new(quote, collateral).map_err(|_| Error::AttestationEvidenceDeserialization)?;
    let verification_output = verifier.verify(&evidence);
    if verification_output.is_success().into() {
        Ok(())
    } else {
        let display_tree = VerificationTreeDisplay::new(&verifier, verification_output);
        Err(Error::AttestationEvidenceVerification(
            VerifierError::Verification(display_tree.to_string()),
        ))
    }
}

/// Ready + Ciphertext => Ready + Vec-of-plaintext
impl<Cipher> Transition<Ready<Cipher>, Ciphertext<'_, '_>, Vec<u8>> for Ready<Cipher>
where
    Cipher: NoiseCipher,
{
    type Error = CipherError;

    fn try_next<R: CryptoRng>(
        self,
        _csprng: &mut R,
        input: Ciphertext,
    ) -> Result<(Ready<Cipher>, Vec<u8>), Self::Error> {
        let mut retval = self;
        let plaintext = retval.decrypt(input.aad, input.msg)?;
        Ok((retval, plaintext))
    }
}

/// Ready + Plaintext => Ready + Vec-of-ciphertext
impl<Cipher> Transition<Ready<Cipher>, Plaintext<'_, '_>, Vec<u8>> for Ready<Cipher>
where
    Cipher: NoiseCipher,
{
    type Error = CipherError;

    fn try_next<R: CryptoRng>(
        self,
        _csprng: &mut R,
        input: Plaintext,
    ) -> Result<(Ready<Cipher>, Vec<u8>), Self::Error> {
        let mut retval = self;
        let ciphertext = retval.encrypt(input.aad, input.msg)?;
        Ok((retval, ciphertext))
    }
}

/// Ready + NonceCiphertext => Ready + Vec
impl<Cipher> Transition<Ready<Cipher>, NonceCiphertext<'_, '_>, Vec<u8>> for Ready<Cipher>
where
    Cipher: NoiseCipher,
{
    type Error = CipherError;

    fn try_next<R: CryptoRng>(
        self,
        _csprng: &mut R,
        input: NonceCiphertext<'_, '_>,
    ) -> Result<(Ready<Cipher>, Vec<u8>), Self::Error> {
        let mut retval = self;
        let plaintext =
            retval.decrypt_with_nonce(input.ciphertext.aad, input.ciphertext.msg, input.nonce)?;
        Ok((retval, plaintext))
    }
}

/// Ready + NoncePlaintext => Ready + (Vec, u64)
impl<Cipher> Transition<Ready<Cipher>, NoncePlaintext<'_, '_>, (Vec<u8>, u64)> for Ready<Cipher>
where
    Cipher: NoiseCipher,
{
    type Error = CipherError;

    fn try_next<R: CryptoRng>(
        self,
        _csprng: &mut R,
        input: NoncePlaintext<'_, '_>,
    ) -> Result<(Ready<Cipher>, (Vec<u8>, u64)), Self::Error> {
        let mut retval = self;
        let output = retval.encrypt_with_nonce(input.aad(), input.msg())?;
        Ok((retval, output))
    }
}
