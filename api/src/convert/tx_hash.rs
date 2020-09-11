//! Convert to/from external::TxHash

use crate::{convert::ConversionError, external};
use mc_transaction_core::tx;
use std::convert::TryFrom;

/// Convert tx::TxHash --> external::TxHash.
impl From<&tx::TxHash> for external::TxHash {
    fn from(other: &tx::TxHash) -> Self {
        let mut tx_hash = external::TxHash::new();
        tx_hash.set_hash(other.to_vec());
        tx_hash
    }
}

/// Convert  external::TxHash --> tx::TxHash.
impl TryFrom<&external::TxHash> for tx::TxHash {
    type Error = ConversionError;

    fn try_from(value: &external::TxHash) -> Result<Self, Self::Error> {
        let hash_bytes: &[u8] = value.get_hash();
        tx::TxHash::try_from(hash_bytes).or(Err(ConversionError::ArrayCastError))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // tx::TxHash --> external::TxHash.
    fn test_tx_hash_from() {
        let source: tx::TxHash = tx::TxHash::from([7u8; 32]);
        let converted = external::TxHash::from(&source);
        assert_eq!(converted.hash.as_slice(), source.as_bytes());
    }

    #[test]
    // external::TxHash --> tx::TxHash
    fn test_tx_hash_try_from() {
        let mut source = external::TxHash::new();
        source.set_hash(vec![7u8; 32]);
        let converted = tx::TxHash::try_from(&source).unwrap();
        assert_eq!(converted.0, [7u8; 32]);
    }

    #[test]
    // Unmarshalling too many bytes into a TxHash should produce an error.
    fn test_tx_hash_try_from_too_many_bytes() {
        let mut source = external::TxHash::new();
        source.set_hash(vec![7u8; 99]); // Too many bytes.
        assert!(tx::TxHash::try_from(&source).is_err());
    }

    #[test]
    // Unmarshalling too few bytes into a TxHash should produce an error.
    fn test_tx_hash_try_from_too_few_bytes() {
        let mut source = external::TxHash::new();
        source.set_hash(vec![7u8; 3]); // Too few bytes.
        assert!(tx::TxHash::try_from(&source).is_err());
    }
}
