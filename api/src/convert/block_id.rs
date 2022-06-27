//! Convert to/from blockchain::BlockID

use crate::{blockchain, ConversionError};
use mc_blockchain_types::BlockID;

impl From<&BlockID> for blockchain::BlockId {
    fn from(src: &BlockID) -> Self {
        Self {
            data: src.as_ref().to_vec(),
        }
    }
}

impl TryFrom<&blockchain::BlockId> for BlockID {
    type Error = ConversionError;

    fn try_from(src: &blockchain::BlockId) -> Result<Self, Self::Error> {
        BlockID::try_from(&src.data[..]).map_err(|_| ConversionError::ArrayCastError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Unmarshalling too many bytes into a BlockID should produce an error.
    fn test_from_blockchain_block_id_error() {
        // Cannot convert 37 bytes to a BlockID.
        let bad_block_id = blockchain::BlockId {
            data: vec![1u8; 37],
        };

        let converted = BlockID::try_from(&bad_block_id);
        assert!(converted.is_err());
    }

    #[test]
    // Unmarshalling too few bytes into a BlockID should produce an error.
    fn test_from_blockchain_block_id_error_two() {
        // Cannot convert 11 bytes to a BlockID.
        let bad_block_id = blockchain::BlockId {
            data: vec![1u8; 11],
        };

        let converted = BlockID::try_from(&bad_block_id);
        assert!(converted.is_err());
    }
}
