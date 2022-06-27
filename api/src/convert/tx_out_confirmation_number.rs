//! Convert to/from external::TxOutConfirmationNumber

use crate::{external, ConversionError};
use mc_transaction_core::tx;

/// Convert tx::TxOutConfirmationNumber --> external::TxOutConfirmationNumber.
impl From<&tx::TxOutConfirmationNumber> for external::TxOutConfirmationNumber {
    fn from(src: &tx::TxOutConfirmationNumber) -> Self {
        Self { hash: src.to_vec() }
    }
}

/// Convert  external::TxOutConfirmationNumber --> tx::TxOutConfirmationNumber.
impl TryFrom<&external::TxOutConfirmationNumber> for tx::TxOutConfirmationNumber {
    type Error = ConversionError;

    fn try_from(src: &external::TxOutConfirmationNumber) -> Result<Self, Self::Error> {
        let bytes: &[u8; 32] = (&src.hash[..])
            .try_into()
            .map_err(|_| ConversionError::ArrayCastError)?;
        Ok(bytes.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // tx::TxOutConfirmationNumber --> external::TxOutConfirmationNumber.
    fn test_confirmation_number_from() {
        let source: tx::TxOutConfirmationNumber = tx::TxOutConfirmationNumber::from([7u8; 32]);
        let converted = external::TxOutConfirmationNumber::from(&source);
        assert_eq!(converted.hash.as_slice(), source.as_ref());
    }

    #[test]
    // external::TxOutConfirmationNumber --> tx::TxOutConfirmationNumber
    fn test_confirmation_number_try_from() {
        let source = external::TxOutConfirmationNumber {
            hash: vec![7u8; 32],
        };

        let converted = tx::TxOutConfirmationNumber::try_from(&source).unwrap();
        assert_eq!(converted.as_ref(), &[7u8; 32]);
    }

    #[test]
    // Unmarshalling too many bytes into a TxOutConfirmationNumber should produce an
    // error.
    fn test_confirmation_number_try_from_too_many_bytes() {
        let source = external::TxOutConfirmationNumber {
            hash: vec![7u8; 99], // Too many bytes.
        };
        assert!(tx::TxOutConfirmationNumber::try_from(&source).is_err());
    }

    #[test]
    // Unmarshalling too few bytes into a TxOutConfirmationNumber should produce an
    // error.
    fn test_confirmation_number_try_from_too_few_bytes() {
        let source = external::TxOutConfirmationNumber {
            hash: vec![7u8; 3], // Too few bytes.
        };
        assert!(tx::TxOutConfirmationNumber::try_from(&source).is_err());
    }
}
