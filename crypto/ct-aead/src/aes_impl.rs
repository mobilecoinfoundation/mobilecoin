use crate::CtAeadDecrypt;

use aes_gcm::{AesGcm, Tag, A_MAX, C_MAX};
use block_cipher::{
    consts::U16,
    generic_array::{ArrayLength, GenericArray},
    Block, BlockCipher,
};

impl<Aes, NonceSize> CtAeadDecrypt for AesGcm<Aes, NonceSize>
where
    Aes: BlockCipher<BlockSize = U16>,
    Aes::ParBlocks: ArrayLength<Block<Aes>>,
    NonceSize: ArrayLength<u8>,
{
    /// A constant time version of the original
    /// https://docs.rs/aes-gcm/0.6.0/src/aes_gcm/lib.rs.html#251
    fn ct_decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> bool {
        if buffer.len() as u64 > C_MAX || associated_data.len() as u64 > A_MAX {
            return false;
        }

        // TODO(tarcieri): interleave encryption with GHASH
        // See: <https://github.com/RustCrypto/AEADs/issues/74>
        let mut expected_tag = self.compute_tag(associated_data, buffer);
        let mut ctr = self.init_ctr(nonce);
        ctr.apply_keystream(&self.cipher, expected_tag.as_mut_slice());
        ctr.apply_keystream(&self.cipher, buffer);

        use subtle::ConstantTimeEq;
        bool::from(expected_tag.ct_eq(&tag))
    }
}
