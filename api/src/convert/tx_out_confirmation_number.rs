// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::TxOutConfirmationNumber

use crate::{external, ConversionError};
use mc_transaction_extra::TxOutConfirmationNumber;

/// Convert TxOutConfirmationNumber --> external::TxOutConfirmationNumber.
impl From<&TxOutConfirmationNumber> for external::TxOutConfirmationNumber {
    fn from(src: &TxOutConfirmationNumber) -> Self {
        let mut tx_confirmation = external::TxOutConfirmationNumber::new();
        tx_confirmation.set_hash(src.to_vec());
        tx_confirmation
    }
}

/// Convert  external::TxOutConfirmationNumber --> TxOutConfirmationNumber.
impl TryFrom<&external::TxOutConfirmationNumber> for TxOutConfirmationNumber {
    type Error = ConversionError;

    fn try_from(src: &external::TxOutConfirmationNumber) -> Result<Self, Self::Error> {
        let bytes: &[u8] = src.get_hash();
        let mut hash = [0u8; 32];
        if bytes.len() != hash.len() {
            return Err(ConversionError::ArrayCastError);
        }
        hash.copy_from_slice(bytes);
        Ok(TxOutConfirmationNumber::from(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // TxOutConfirmationNumber --> external::TxOutConfirmationNumber.
    fn test_confirmation_number_from() {
        let source: TxOutConfirmationNumber = TxOutConfirmationNumber::from([7u8; 32]);
        let converted = external::TxOutConfirmationNumber::from(&source);
        assert_eq!(converted.hash.as_slice(), source.as_ref());
    }

    #[test]
    // external::TxOutConfirmationNumber --> TxOutConfirmationNumber
    fn test_confirmation_number_try_from() {
        let mut source = external::TxOutConfirmationNumber::new();
        source.set_hash(vec![7u8; 32]);
        let converted = TxOutConfirmationNumber::try_from(&source).unwrap();
        assert_eq!(*converted.as_ref(), [7u8; 32]);
    }

    #[test]
    // Unmarshalling too many bytes into a TxOutConfirmationNumber should produce an
    // error.
    fn test_confirmation_number_try_from_too_many_bytes() {
        let mut source = external::TxOutConfirmationNumber::new();
        source.set_hash(vec![7u8; 99]); // Too many bytes.
        assert!(TxOutConfirmationNumber::try_from(&source).is_err());
    }

    #[test]
    // Unmarshalling too few bytes into a TxOutConfirmationNumber should produce an
    // error.
    fn test_confirmation_number_try_from_too_few_bytes() {
        let mut source = external::TxOutConfirmationNumber::new();
        source.set_hash(vec![7u8; 3]); // Too few bytes.
        assert!(TxOutConfirmationNumber::try_from(&source).is_err());
    }
}
