// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_transaction_core::ring_ct::OutputSecret.

use crate::{external, ConversionError};
use mc_transaction_core::ring_ct::OutputSecret;

impl From<&OutputSecret> for external::OutputSecret {
    fn from(source: &OutputSecret) -> Self {
        Self {
            amount: Some((&source.amount).into()),
            blinding: Some((&source.blinding).into()),
        }
    }
}

impl TryFrom<&external::OutputSecret> for OutputSecret {
    type Error = ConversionError;

    fn try_from(source: &external::OutputSecret) -> Result<Self, Self::Error> {
        let amount = source.amount.as_ref().unwrap_or(&Default::default()).into();
        let blinding = source
            .blinding
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        Ok(OutputSecret { amount, blinding })
    }
}

#[cfg(test)]
mod tests {
    use crate::external;
    use curve25519_dalek::scalar::Scalar;
    use mc_transaction_core::{ring_ct::OutputSecret, Amount, TokenId};
    use rand::{rngs::StdRng, SeedableRng};

    // Test converting between external::OutputSecret and
    // mc_transaction_core::ring_ct::OutputSecret
    #[test]
    fn test_output_secret_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        let output_secret = OutputSecret {
            amount: Amount::new(10000, TokenId::from(10)),
            blinding: Scalar::random(&mut rng),
        };

        let output_secret_external: external::OutputSecret = (&output_secret).into();
        let deserialized_output_secret: OutputSecret =
            (&output_secret_external).try_into().unwrap();

        assert_eq!(output_secret, deserialized_output_secret);
    }
}
