// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_crypto_ring_signature_signer::InputSecret.

use crate::{external, ConversionError};
use mc_crypto_ring_signature_signer::{InputSecret, OneTimeKeyDeriveData};

impl From<&InputSecret> for external::InputSecret {
    fn from(source: &InputSecret) -> Self {
        let mut input_secret = external::InputSecret::new();
        match source.onetime_key_derive_data {
            OneTimeKeyDeriveData::OneTimeKey(onetime_private_key) => {
                input_secret.set_onetime_private_key((&onetime_private_key).into())
            }
            OneTimeKeyDeriveData::SubaddressIndex(subaddress_index) => {
                input_secret.set_subaddress_index(subaddress_index)
            }
        }
        input_secret.set_amount((&source.amount).into());
        input_secret.set_blinding((&source.blinding).into());
        input_secret
    }
}

impl TryFrom<&external::InputSecret_oneof_onetime_key_derive_data> for OneTimeKeyDeriveData {
    type Error = ConversionError;

    fn try_from(
        source: &external::InputSecret_oneof_onetime_key_derive_data,
    ) -> Result<Self, Self::Error> {
        match source {
            external::InputSecret_oneof_onetime_key_derive_data::onetime_private_key(
                onetime_private_key,
            ) => Ok(OneTimeKeyDeriveData::OneTimeKey(
                onetime_private_key.try_into()?,
            )),
            external::InputSecret_oneof_onetime_key_derive_data::subaddress_index(
                subaddress_index,
            ) => Ok(OneTimeKeyDeriveData::SubaddressIndex(*subaddress_index)),
        }
    }
}

impl TryFrom<&external::InputSecret> for InputSecret {
    type Error = ConversionError;

    fn try_from(source: &external::InputSecret) -> Result<Self, Self::Error> {
        let onetime_key_derive_data: OneTimeKeyDeriveData = source
            .onetime_key_derive_data
            .as_ref()
            .ok_or_else(|| {
                ConversionError::MissingField("InputSecret.onetime_key_derive_data".to_string())
            })?
            .try_into()?;
        Ok(InputSecret {
            onetime_key_derive_data,
            amount: source.get_amount().into(),
            blinding: source.get_blinding().try_into()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::external;
    use curve25519_dalek::scalar::Scalar;
    use mc_crypto_keys::RistrettoPrivate;
    use mc_crypto_ring_signature_signer::{InputSecret, OneTimeKeyDeriveData};
    use mc_transaction_core::{Amount, TokenId};
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    // Test converting between external::InputSecret and
    // mc_crypto_ring_signature_signer::InputSecret
    #[test]
    fn test_input_secret_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        let input_secret = InputSecret {
            onetime_key_derive_data: OneTimeKeyDeriveData::SubaddressIndex(10),
            amount: Amount::new(10000, TokenId::from(0)),
            blinding: Scalar::random(&mut rng),
        };

        let input_secret_external: external::InputSecret = (&input_secret).into();
        let input_secret_decrypted: InputSecret = (&input_secret_external).try_into().unwrap();

        assert_eq!(input_secret, input_secret_decrypted);

        let input_secret = InputSecret {
            onetime_key_derive_data: OneTimeKeyDeriveData::OneTimeKey(
                RistrettoPrivate::from_random(&mut rng),
            ),
            amount: Amount::new(10000, TokenId::from(0)),
            blinding: Scalar::random(&mut rng),
        };

        let input_secret_external: external::InputSecret = (&input_secret).into();
        let input_secret_decrypted: InputSecret = (&input_secret_external).try_into().unwrap();

        assert_eq!(input_secret, input_secret_decrypted);
    }
}
