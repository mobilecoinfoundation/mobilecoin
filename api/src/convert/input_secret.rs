// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_crypto_ring_signature_signer::InputSecret.

use crate::{external, external::input_secret, ConversionError};
use mc_crypto_ring_signature_signer::{InputSecret, OneTimeKeyDeriveData};

impl From<&InputSecret> for external::InputSecret {
    fn from(source: &InputSecret) -> Self {
        let onetime_key_derive_data = match source.onetime_key_derive_data {
            OneTimeKeyDeriveData::OneTimeKey(onetime_private_key) => {
                input_secret::OnetimeKeyDeriveData::OnetimePrivateKey((&onetime_private_key).into())
            }
            OneTimeKeyDeriveData::SubaddressIndex(subaddress_index) => {
                input_secret::OnetimeKeyDeriveData::SubaddressIndex(subaddress_index)
            }
        };
        Self {
            amount: Some((&source.amount).into()),
            blinding: Some((&source.blinding).into()),
            onetime_key_derive_data: Some(onetime_key_derive_data),
        }
    }
}

impl TryFrom<&external::input_secret::OnetimeKeyDeriveData> for OneTimeKeyDeriveData {
    type Error = ConversionError;

    fn try_from(
        source: &external::input_secret::OnetimeKeyDeriveData,
    ) -> Result<Self, Self::Error> {
        match source {
            external::input_secret::OnetimeKeyDeriveData::OnetimePrivateKey(
                onetime_private_key,
            ) => Ok(OneTimeKeyDeriveData::OneTimeKey(
                onetime_private_key.try_into()?,
            )),
            external::input_secret::OnetimeKeyDeriveData::SubaddressIndex(subaddress_index) => {
                Ok(OneTimeKeyDeriveData::SubaddressIndex(*subaddress_index))
            }
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
            amount: source.amount.as_ref().unwrap_or(&Default::default()).into(),
            blinding: source
                .blinding
                .as_ref()
                .unwrap_or(&Default::default())
                .try_into()?,
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
            amount: Amount::new(10000, TokenId::from(10)),
            blinding: Scalar::random(&mut rng),
        };

        let external_input_secret: external::InputSecret = (&input_secret).into();
        let recovered_input_secret: InputSecret = (&external_input_secret).try_into().unwrap();

        assert_eq!(input_secret, recovered_input_secret);

        let input_secret = InputSecret {
            onetime_key_derive_data: OneTimeKeyDeriveData::OneTimeKey(
                RistrettoPrivate::from_random(&mut rng),
            ),
            amount: Amount::new(10000, TokenId::from(10)),
            blinding: Scalar::random(&mut rng),
        };

        let external_input_secret: external::InputSecret = (&input_secret).into();
        let recovered_input_secret: InputSecret = (&external_input_secret).try_into().unwrap();

        assert_eq!(input_secret, recovered_input_secret);
    }
}
