// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from printable::TxOutGiftCode

use crate::{printable, ConversionError};
use mc_transaction_extra::TxOutGiftCode;

/// Convert TxOutGiftCode --> printable::TxOutGiftCode.
impl From<&TxOutGiftCode> for printable::TxOutGiftCode {
    fn from(src: &TxOutGiftCode) -> Self {
        Self {
            global_index: src.global_index,
            onetime_private_key: Some((&src.onetime_private_key).into()),
            shared_secret: Some((&src.shared_secret).into()),
        }
    }
}

/// Convert from printable::TxOutGiftCode --> TxOutGiftCode
impl TryFrom<&printable::TxOutGiftCode> for TxOutGiftCode {
    type Error = ConversionError;

    fn try_from(src: &printable::TxOutGiftCode) -> Result<Self, Self::Error> {
        let onetime_private_key = src
            .onetime_private_key
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        let shared_secret = src
            .shared_secret
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;

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
    use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
    use mc_util_from_random::FromRandom;
    use mc_util_serial::{decode, encode};
    use prost::Message;
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    #[test]
    // test conversion between TxOutGiftCode <-->
    // printable::TxOutGiftCode.
    fn test_gift_code_serialization() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let source = TxOutGiftCode::new(
            9001,
            RistrettoPrivate::from_random(&mut rng),
            RistrettoPublic::from_random(&mut rng),
        );

        // Roundtrip from protobuf should return the same object
        {
            let external = printable::TxOutGiftCode::from(&source);
            let recovered = TxOutGiftCode::try_from(&external).unwrap();
            assert_eq!(source, recovered);
        }

        // Prost decode(encode(source)) should produce the same object
        {
            let bytes = encode(&source);
            let recovered = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }

        // Encoding with prost, decoding with protobuf should produce the same object
        {
            let bytes = encode(&source);
            let recovered = printable::TxOutGiftCode::decode(bytes.as_slice()).unwrap();
            assert_eq!(recovered, printable::TxOutGiftCode::from(&source));
        }

        // Encoding with protobuf, decoding with prost should produce the same object
        {
            let external = printable::TxOutGiftCode::from(&source);
            let bytes = external.encode_to_vec();
            let recovered: TxOutGiftCode = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }
    }
}
