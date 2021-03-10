//! Convert to/from blockchain::BlockContentsHash

use crate::{blockchain, convert::ConversionError};
use std::convert::TryFrom;

/// Convert mc_transaction_core::BlockContentsHash -->
/// blockchain::BlockContentsHash.
impl From<&mc_transaction_core::BlockContentsHash> for blockchain::BlockContentsHash {
    fn from(src: &mc_transaction_core::BlockContentsHash) -> Self {
        let mut dst = blockchain::BlockContentsHash::new();
        dst.set_data(src.as_ref().to_vec());
        dst
    }
}

/// Convert blockchain::BlockContentsHash -->
/// mc_transaction_core::BlockContentsHash.
impl TryFrom<&blockchain::BlockContentsHash> for mc_transaction_core::BlockContentsHash {
    type Error = ConversionError;

    fn try_from(src: &blockchain::BlockContentsHash) -> Result<Self, Self::Error> {
        mc_transaction_core::BlockContentsHash::try_from(src.get_data())
            .map_err(|_| ConversionError::ArrayCastError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Unmarshalling too many bytes into a BlockContentsHash should produce an
    // error.
    fn test_from_blockchain_block_contents_hash_error() {
        // Cannot convert 37 bytes to a BlockContentsHash.
        let mut bad_block_contents_hash = blockchain::BlockContentsHash::new();
        bad_block_contents_hash.set_data(vec![1u8; 37]);

        let converted = mc_transaction_core::BlockContentsHash::try_from(&bad_block_contents_hash);
        assert!(converted.is_err());
    }

    #[test]
    // Unmarshalling too few bytes into a BlockContentsHash should produce an error.
    fn test_from_blockchain_block_contents_hash_error_two() {
        // Cannot convert 11 bytes to a BlockContentsHash.
        let mut bad_block_contents_hash = blockchain::BlockContentsHash::new();
        bad_block_contents_hash.set_data(vec![1u8; 11]);

        let converted = mc_transaction_core::BlockContentsHash::try_from(&bad_block_contents_hash);
        assert!(converted.is_err());
    }
}
