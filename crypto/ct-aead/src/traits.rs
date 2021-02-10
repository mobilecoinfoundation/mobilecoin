use aead::AeadInPlace;
use block_cipher::generic_array::GenericArray;
use subtle::Choice;

/// API for Aead in-place decryption which is constant-time with respect to
/// the mac check failing
///
/// This is meant to extend the AeadInPlace trait and be implemented by those
/// AEAD's which have a constant-time decrypt operation.
pub trait CtAeadDecrypt: AeadInPlace {
    /// Decrypt a buffer using given aead nonce, validating associated data
    /// under the mac (tag).
    ///
    /// This API promises to be branchless and constant time, particularly,
    /// not branching on whether or not the mac check succeeded.
    ///
    /// Returns:
    /// Choice::from(true): The mac check succeeded and the buffer contains the plaintext
    /// Choice::from(false): Decryption failed, and the buffer contains failed decryption.
    ///        The caller SHOULD zeroize buffer before it is discarded.
    fn ct_decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> CtDecryptResult;
}

/// A new-type wrapper around choice with the #[must_use] annotation that Result has.
/// This wraps the value Choice::from(true) when decryption succeeded, and Choice::from(false) otherwise.
#[must_use = "The result of constant time decryption should not be discarded"]
#[derive(Copy, Clone, Debug)]
pub struct CtDecryptResult(pub Choice);

impl AsRef<Choice> for CtDecryptResult {
    fn as_ref(&self) -> &Choice {
        &self.0
    }
}

impl From<Choice> for CtDecryptResult {
    fn from(src: Choice) -> Self {
        CtDecryptResult(src)
    }
}

impl From<CtDecryptResult> for Choice {
    fn from(src: CtDecryptResult) -> Choice {
        src.0
    }
}

impl From<CtDecryptResult> for bool {
    fn from(src: CtDecryptResult) -> bool {
        bool::from(Choice::from(src))
    }
}
