use aead::AeadInPlace;
use block_cipher::generic_array::GenericArray;

/// API for Aead in-place decryption which is constant-time with respect to
/// the mac check failing
pub trait CtAeadDecrypt: AeadInPlace {
    /// Decrypt a buffer using given aead nonce, validating associated data
    /// under the mac (tag).
    ///
    /// This API promises to be branchless and constant time, particularly,
    /// not branching on whether or not the mac check succeeded.
    ///
    /// Returns:
    /// true: The mac check succeeded and the buffer contains the plaintext
    /// false: The mac check failed, and the buffer contains failed decryption.
    ///        The caller should zeroize buffer before it is discarded.
    fn ct_decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> bool;
}
