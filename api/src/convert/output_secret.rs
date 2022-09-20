// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_transaction_core::ring_ct::OutputSecret.

use crate::{external, ConversionError};
use mc_transaction_core::ring_ct::OutputSecret;

impl From<&OutputSecret> for external::OutputSecret {
    fn from(source: &OutputSecret) -> Self {
        let mut output_secret = external::OutputSecret::new();
        output_secret.set_amount((&source.amount).into());
        output_secret.set_blinding((&source.blinding).into());
        output_secret
    }
}

impl TryFrom<&external::OutputSecret> for OutputSecret {
    type Error = ConversionError;

    fn try_from(source: &external::OutputSecret) -> Result<Self, Self::Error> {
        Ok(OutputSecret {
            amount: source
                .get_amount()
                .try_into()
                .map_err(|_| ConversionError::KeyCastError)?,
            blinding: source.get_blinding().try_into()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::external;
    use curve25519_dalek::scalar::Scalar;
    use mc_transaction_core::{ring_ct::OutputSecret, Amount, TokenId};
    use rand::{rngs::StdRng, SeedableRng};

    // Test converting between external::ReducedTxOut and
    // mc_transaction_core::ring_signature::ReducedTxOut
    #[test]
    fn test_output_secret_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        let output_secret = OutputSecret {
            amount: Amount::new(10000, TokenId::from(0)),
            blinding: Scalar::random(&mut rng),
        };

        let output_secret_external: external::OutputSecret = (&output_secret).into();
        let deserialized_output_secret: OutputSecret =
            (&output_secret_external).try_into().unwrap();

        assert_eq!(output_secret, deserialized_output_secret);
    }
}
