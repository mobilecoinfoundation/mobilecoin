// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from printable::TxOutGiftCode

use crate::{printable, ConversionError};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_transaction_core::TxOutGiftCode;

/// Convert mc_transaction_core::TxOutGiftCode --> printable::TxOutGiftCode.
impl From<&TxOutGiftCode> for printable::TxOutGiftCode {
    fn from(src: &TxOutGiftCode) -> Self {
        Self {
            global_index: src.global_index,
            onetime_private_key: Some((&src.onetime_private_key).into()),
            shared_secret: Some((&src.shared_secret).into()),
        }
    }
}

/// Convert from printable::TxOutGiftCode --> mc_transaction_core::TxOutGiftCode
impl TryFrom<&printable::TxOutGiftCode> for TxOutGiftCode {
    type Error = ConversionError;

    fn try_from(src: &printable::TxOutGiftCode) -> Result<Self, Self::Error> {
        let onetime_private_key = src
            .onetime_private_key
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;
        let compressed_shared_secret = CompressedRistrettoPublic::try_from(
            src.shared_secret
                .as_ref()
                .ok_or(ConversionError::ObjectMissing)?,
        )?;
        let shared_secret = RistrettoPublic::try_from(&compressed_shared_secret)?;

        Ok(Self {
            global_index: src.global_index,
            onetime_private_key,
            shared_secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_crypto_keys::RistrettoPrivate;
    use mc_transaction_core::TxOutGiftCode;
    use mc_util_from_random::FromRandom;
    use mc_util_serial::round_trip_message;
    use mc_util_test_helper::get_seeded_rng;

    #[test]
    // test conversion between mc_transaction_core::TxOutGiftCode <-->
    // printable::TxOutGiftCode.
    fn test_gift_code_serialization() {
        let mut rng = get_seeded_rng();
        let source = TxOutGiftCode::new(
            9001,
            RistrettoPrivate::from_random(&mut rng),
            RistrettoPublic::from_random(&mut rng),
        );

        round_trip_message::<TxOutGiftCode, printable::TxOutGiftCode>(&source)
    }
}
