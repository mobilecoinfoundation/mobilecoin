// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from printable::TxOutGiftCode

use crate::{external, printable, ConversionError};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
use std::convert::TryFrom;

/// Convert mc_transaction_core::TxOutGiftCode --> printable::TxOutGiftCode.
impl From<&mc_transaction_core::TxOutGiftCode> for printable::TxOutGiftCode {
    fn from(src: &mc_transaction_core::TxOutGiftCode) -> Self {
        let mut tx_out_gift_code = printable::TxOutGiftCode::new();
        tx_out_gift_code.set_global_index(src.global_index);
        tx_out_gift_code
            .set_onetime_private_key(external::RistrettoPrivate::from(&src.onetime_private_key));
        tx_out_gift_code.set_shared_secret(external::CompressedRistretto::from(&src.shared_secret));

        tx_out_gift_code
    }
}

/// Convert from printable::TxOutGiftCode --> mc_transaction_core::TxOutGiftCode
impl TryFrom<&printable::TxOutGiftCode> for mc_transaction_core::TxOutGiftCode {
    type Error = ConversionError;

    fn try_from(src: &printable::TxOutGiftCode) -> Result<Self, Self::Error> {
        let global_index = src.get_global_index();
        let onetime_private_key = RistrettoPrivate::try_from(src.get_onetime_private_key())?;
        let compressed_shared_secret = CompressedRistrettoPublic::try_from(src.get_shared_secret())?
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
    use mc_transaction_core::TxOutGiftCode;
    use mc_util_from_random::FromRandom;
    use mc_util_serial::{decode, encode};
    use protobuf::Message;
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    #[test]
    // test conversion between mc_transaction_core::TxOutGiftCode <-->
    // printable::TxOutGiftCode.
    fn test_gift_code_serialization() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let source = mc_transaction_core::TxOutGiftCode::new(
            9001,
            RistrettoPrivate::from_random(&mut rng),
            RistrettoPublic::from_random(&mut rng),
        );

        // Roundtrip from protobuf should return the same object
        {
            let external = printable::TxOutGiftCode::from(&source);
            let recovered = mc_transaction_core::TxOutGiftCode::try_from(&external).unwrap();
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
            let recovered = printable::TxOutGiftCode::parse_from_bytes(&bytes).unwrap();
            assert_eq!(recovered, printable::TxOutGiftCode::from(&source));
        }

        // Encoding with protobuf, decoding with prost should produce the same object
        {
            let external = printable::TxOutGiftCode::from(&source);
            let bytes = external.write_to_bytes().unwrap();
            let recovered: TxOutGiftCode = decode(&bytes).unwrap();
            assert_eq!(source, recovered);
        }
    }
}
