// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from blockchain::BlockID

use crate::{blockchain, ConversionError};
use mc_blockchain_types::BlockID;

/// Convert BlockID --> blockchain::BlockID.
impl From<&BlockID> for blockchain::BlockID {
    fn from(src: &BlockID) -> Self {
        let mut dst = blockchain::BlockID::new();
        dst.set_data(src.as_ref().to_vec());
        dst
    }
}

/// Convert blockchain::BlockID --> BlockID.
impl TryFrom<&blockchain::BlockID> for BlockID {
    type Error = ConversionError;

    fn try_from(src: &blockchain::BlockID) -> Result<Self, Self::Error> {
        BlockID::try_from(src.get_data()).map_err(|_| ConversionError::ArrayCastError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Unmarshalling too many bytes into a BlockID should produce an error.
    fn test_from_blockchain_block_id_error() {
        // Cannot convert 37 bytes to a BlockID.
        let mut bad_block_id = blockchain::BlockID::new();
        bad_block_id.set_data(vec![1u8; 37]);

        let converted = BlockID::try_from(&bad_block_id);
        assert!(converted.is_err());
    }

    #[test]
    // Unmarshalling too few bytes into a BlockID should produce an error.
    fn test_from_blockchain_block_id_error_two() {
        // Cannot convert 11 bytes to a BlockID.
        let mut bad_block_id = blockchain::BlockID::new();
        bad_block_id.set_data(vec![1u8; 11]);

        let converted = BlockID::try_from(&bad_block_id);
        assert!(converted.is_err());
    }
}
