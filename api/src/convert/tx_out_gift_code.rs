//! Convert to/from printable::TxOutGiftCode

use crate::{external, printable, ConversionError};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
use std::convert::TryFrom;

/// Convert mc_transaction_core::GiftCode --> printable::GiftCode.
impl From<&mc_transaction_core::GiftCode> for printable::GiftCode {
    fn from(src: &mc_transaction_core::GiftCode) -> Self {
        let mut gift_code = printable::GiftCode::new();
        gift_code.set_global_index(src.global_index);
        gift_code
            .set_onetime_private_key(external::RistrettoPrivate::from(&src.onetime_private_key));
        gift_code.set_shared_secret(external::CompressedRistretto::from(&src.shared_secret));

        gift_code
    }
}

/// Convert from printable::GiftCode --> mc_transaction_core::GiftCode
impl TryFrom<&printable::GiftCode> for mc_transaction_core::GiftCode {
    type Error = ConversionError;

    fn try_from(src: &printable::GiftCode) -> Result<Self, Self::Error> {
        let global_index = src.get_global_index();
        let onetime_private_key = RistrettoPrivate::try_from(src.get_onetime_private_key())?;
        let compressed_shared_secret = CompressedRistrettoPublic::try_from(src.get_shared_secret())
            .map_err(|_| ConversionError::ArrayCastError)?;
        let shared_secret = RistrettoPublic::try_from(&compressed_shared_secret)?;

        Ok(Self {
            global_index,
            onetime_private_key,
            shared_secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_util_from_random::FromRandom;
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    #[test]
    // test conversion between mc_transaction_core::GiftCode <-->
    // printable::GiftCode.
    fn test_gift_code_serialization() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let gift_code_input = mc_transaction_core::GiftCode::new(
            9001,
            RistrettoPrivate::from_random(&mut rng),
            RistrettoPublic::from_random(&mut rng),
        );
        let external = printable::GiftCode::from(&gift_code_input);
        let recovered = mc_transaction_core::GiftCode::try_from(&external).unwrap();
        assert_eq!(gift_code_input, recovered);
    }
}
