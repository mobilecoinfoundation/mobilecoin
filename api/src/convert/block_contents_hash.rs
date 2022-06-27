//! Convert to/from blockchain::BlockContentsHash

use crate::{blockchain, ConversionError};
use mc_blockchain_types::BlockContentsHash;

/// Convert BlockContentsHash --> blockchain::BlockContentsHash.
impl From<&BlockContentsHash> for blockchain::BlockContentsHash {
    fn from(src: &BlockContentsHash) -> Self {
        Self {
            data: src.as_ref().to_vec(),
        }
    }
}

/// Convert blockchain::BlockContentsHash --> BlockContentsHash.
impl TryFrom<&blockchain::BlockContentsHash> for BlockContentsHash {
    type Error = ConversionError;

    fn try_from(src: &blockchain::BlockContentsHash) -> Result<Self, Self::Error> {
        BlockContentsHash::try_from(&src.data[..]).map_err(|_| ConversionError::ArrayCastError)
    }
}

#[cfg(test)]
mod tests {
    use mc_util_serial::round_trip_message;

    use super::*;

    #[test]
    fn test_round_trip() {
        let hash = BlockContentsHash([42; 32]);
        round_trip_message::<BlockContentsHash, blockchain::BlockContentsHash>(&hash);
    }

    #[test]
    // Unmarshalling too many bytes into a BlockContentsHash should produce an
    // error.
    fn test_from_blockchain_block_contents_hash_error() {
        // Cannot convert 37 bytes to a BlockContentsHash.
        let bad_block_contents_hash = blockchain::BlockContentsHash {
            data: vec![1u8; 37],
        };

        let converted = BlockContentsHash::try_from(&bad_block_contents_hash);
        assert!(converted.is_err());
    }

    #[test]
    // Unmarshalling too few bytes into a BlockContentsHash should produce an error.
    fn test_from_blockchain_block_contents_hash_error_two() {
        // Cannot convert 11 bytes to a BlockContentsHash.
        let bad_block_contents_hash = blockchain::BlockContentsHash {
            data: vec![1u8; 11],
        };

        let converted = BlockContentsHash::try_from(&bad_block_contents_hash);
        assert!(converted.is_err());
    }
}
