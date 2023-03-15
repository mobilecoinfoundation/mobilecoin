// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Utilities for converting between `mobilecoind` and `mobilecoind_api` data
//! types.

use crate::{
    payments::{Outlay, OutlayV2, SciForTx, TxProposal},
    utxo_store::UnspentTxOut,
};
use mc_account_keys::PublicAddress;
use mc_api::ConversionError;
use mc_common::HashMap;
use mc_mobilecoind_api as api;
use mc_transaction_core::{
    ring_signature::KeyImage,
    tx::{Tx, TxOut},
    Amount, TokenId,
};
use mc_transaction_extra::TxOutConfirmationNumber;
use protobuf::RepeatedField;

impl From<&UnspentTxOut> for api::UnspentTxOut {
    fn from(src: &UnspentTxOut) -> Self {
        let mut dst = Self::new();

        dst.set_tx_out((&src.tx_out).into());
        dst.set_subaddress_index(src.subaddress_index);
        dst.set_key_image((&src.key_image).into());
        dst.set_value(src.value);
        dst.set_attempted_spend_height(src.attempted_spend_height);
        dst.set_attempted_spend_tombstone(src.attempted_spend_tombstone);
        dst.set_token_id(src.token_id);

        dst
    }
}

impl TryFrom<&api::UnspentTxOut> for UnspentTxOut {
    type Error = ConversionError;

    fn try_from(src: &api::UnspentTxOut) -> Result<Self, Self::Error> {
        let tx_out = TxOut::try_from(src.get_tx_out())?;
        let subaddress_index = src.subaddress_index;
        let key_image = KeyImage::try_from(src.get_key_image())?;
        let value = src.value;
        let attempted_spend_height = src.attempted_spend_height;
        let attempted_spend_tombstone = src.attempted_spend_tombstone;
        let token_id = src.token_id;

        Ok(Self {
            tx_out,
            subaddress_index,
            key_image,
            value,
            attempted_spend_height,
            attempted_spend_tombstone,
            token_id,
        })
    }
}

impl From<&Outlay> for api::Outlay {
    fn from(src: &Outlay) -> Self {
        let mut dst = Self::new();

        dst.set_value(src.value);
        dst.set_receiver((&src.receiver).into());

        dst
    }
}

impl TryFrom<&api::Outlay> for Outlay {
    type Error = ConversionError;

    fn try_from(src: &api::Outlay) -> Result<Self, Self::Error> {
        let value = src.value;
        let receiver = PublicAddress::try_from(src.get_receiver())?;

        Ok(Self { value, receiver })
    }
}

impl From<&OutlayV2> for api::OutlayV2 {
    fn from(src: &OutlayV2) -> Self {
        let mut dst = Self::new();

        dst.set_value(src.amount.value);
        dst.set_token_id(*src.amount.token_id);
        dst.set_receiver((&src.receiver).into());

        dst
    }
}

impl TryFrom<&api::OutlayV2> for OutlayV2 {
    type Error = ConversionError;

    fn try_from(src: &api::OutlayV2) -> Result<Self, Self::Error> {
        let amount = Amount::new(src.value, TokenId::from(src.token_id));
        let receiver = PublicAddress::try_from(src.get_receiver())?;

        Ok(Self { amount, receiver })
    }
}

impl From<&TxProposal> for api::TxProposal {
    fn from(src: &TxProposal) -> api::TxProposal {
        let mut dst = api::TxProposal::new();

        dst.set_input_list(RepeatedField::from_vec(
            src.utxos.iter().map(|utxo| utxo.into()).collect(),
        ));
        dst.set_outlay_list(RepeatedField::from_vec(
            src.outlays.iter().map(|outlay| outlay.into()).collect(),
        ));
        dst.set_tx((&src.tx).into());
        dst.set_fee(src.tx.prefix.fee);
        dst.set_outlay_index_to_tx_out_index(
            src.outlay_index_to_tx_out_index
                .iter()
                .map(|(key, val)| (*key as u64, *val as u64))
                .collect(),
        );
        dst.set_outlay_confirmation_numbers(
            src.outlay_confirmation_numbers
                .iter()
                .map(|val| val.to_vec())
                .collect(),
        );
        dst.set_scis(src.scis.iter().map(Into::into).collect());

        dst
    }
}

impl TryFrom<&api::TxProposal> for TxProposal {
    type Error = ConversionError;

    fn try_from(src: &api::TxProposal) -> Result<Self, Self::Error> {
        if src.fee != src.get_tx().get_prefix().fee {
            return Err(ConversionError::FeeMismatch);
        }

        let utxos = src
            .get_input_list()
            .iter()
            .map(UnspentTxOut::try_from)
            .collect::<Result<Vec<UnspentTxOut>, ConversionError>>()?;

        let outlays: Vec<OutlayV2> = src
            .get_outlay_list()
            .iter()
            .map(OutlayV2::try_from)
            .collect::<Result<_, _>>()?;

        let scis: Vec<SciForTx> = src
            .get_scis()
            .iter()
            .map(SciForTx::try_from)
            .collect::<Result<_, _>>()?;

        let tx = Tx::try_from(src.get_tx())?;

        let outlay_index_to_tx_out_index = src
            .get_outlay_index_to_tx_out_index()
            .iter()
            .map(|(key, val)| (*key as usize, *val as usize))
            .collect::<HashMap<_, _>>();

        // Check that none of the indices are out of bound.
        if outlay_index_to_tx_out_index.len() != outlays.len() {
            return Err(ConversionError::IndexOutOfBounds);
        }

        for (outlay_index, tx_out_index) in outlay_index_to_tx_out_index.iter() {
            if *outlay_index >= outlays.len() || *tx_out_index >= tx.prefix.outputs.len() {
                return Err(ConversionError::IndexOutOfBounds);
            }
        }

        let outlay_confirmation_numbers = src
            .get_outlay_confirmation_numbers()
            .iter()
            .map(|src| match src.len() {
                32 => {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(src);
                    Ok(TxOutConfirmationNumber::from(bytes))
                }
                _ => Err(ConversionError::IndexOutOfBounds),
            })
            .collect::<Result<Vec<TxOutConfirmationNumber>, ConversionError>>()?;

        Ok(Self {
            utxos,
            outlays,
            tx,
            outlay_index_to_tx_out_index,
            outlay_confirmation_numbers,
            scis,
        })
    }
}

impl From<&SciForTx> for api::SciForTx {
    fn from(src: &SciForTx) -> Self {
        let mut dst = Self::new();
        dst.set_sci((&src.sci).into());
        dst.set_partial_fill_value(src.partial_fill_value);
        dst
    }
}

impl TryFrom<&api::SciForTx> for SciForTx {
    type Error = ConversionError;

    fn try_from(src: &api::SciForTx) -> Result<Self, Self::Error> {
        let sci = src.get_sci().try_into()?;
        let partial_fill_value = src.partial_fill_value;

        Ok(Self {
            sci,
            partial_fill_value,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_account_keys::AccountKey;
    use mc_crypto_keys::RistrettoPrivate;
    use mc_ledger_db::{
        test_utils::{create_ledger, create_transaction, initialize_ledger},
        Ledger,
    };
    use mc_transaction_core::{tokens::Mob, Amount, BlockVersion, Token};
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_unspent_tx_out_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        // Rust -> Proto
        let amount = Amount {
            value: 1u64 << 13,
            token_id: Mob::ID,
        };
        let tx_out = TxOut::new(
            BlockVersion::MAX,
            amount,
            &PublicAddress::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let subaddress_index = 123;
        let key_image = KeyImage::from(456);
        let value = 789;
        let attempted_spend_height = 1000;
        let attempted_spend_tombstone = 1234;

        let rust = UnspentTxOut {
            tx_out: tx_out.clone(),
            subaddress_index,
            key_image,
            value,
            attempted_spend_height,
            attempted_spend_tombstone,
            token_id: *Mob::ID,
        };

        let proto = api::UnspentTxOut::from(&rust);

        assert_eq!(tx_out, TxOut::try_from(proto.get_tx_out()).unwrap());
        assert_eq!(subaddress_index, proto.subaddress_index);
        assert_eq!(
            key_image,
            KeyImage::try_from(proto.get_key_image()).unwrap()
        );
        assert_eq!(value, proto.value);
        assert_eq!(attempted_spend_height, proto.attempted_spend_height);
        assert_eq!(attempted_spend_tombstone, proto.attempted_spend_tombstone);

        // Proto -> Rust
        assert_eq!(rust, UnspentTxOut::try_from(&proto).unwrap());
    }

    #[test]
    fn test_outlay_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let public_addr = AccountKey::random(&mut rng).default_subaddress();

        // Rust -> Proto
        let rust = Outlay {
            receiver: public_addr.clone(),
            value: 1234,
        };
        let proto = api::Outlay::from(&rust);

        assert_eq!(proto.value, rust.value);
        assert_eq!(
            PublicAddress::try_from(proto.get_receiver()).unwrap(),
            public_addr
        );

        // Proto -> Rust
        assert_eq!(rust, Outlay::try_from(&proto).unwrap());
    }

    #[test]
    fn test_tx_proposal_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let tx = {
            let mut ledger = create_ledger();
            let sender = AccountKey::random(&mut rng);
            let recipient = AccountKey::random(&mut rng);
            initialize_ledger(BlockVersion::MAX, &mut ledger, 1, &sender, &mut rng);

            let block_contents = ledger.get_block_contents(0).unwrap();
            let tx_out = block_contents.outputs[0].clone();

            create_transaction(
                BlockVersion::MAX,
                &mut ledger,
                &tx_out,
                &sender,
                &recipient.default_subaddress(),
                10,
                &mut rng,
            )
        };

        let utxo = {
            let amount = Amount {
                value: 1u64 << 13,
                token_id: Mob::ID,
            };
            let tx_out = TxOut::new(
                BlockVersion::MAX,
                amount,
                &PublicAddress::from_random(&mut rng),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
            )
            .unwrap();

            let subaddress_index = 123;
            let key_image = KeyImage::from(456);
            let value = 789;
            let attempted_spend_height = 1000;
            let attempted_spend_tombstone = 1234;

            UnspentTxOut {
                tx_out,
                subaddress_index,
                key_image,
                value,
                attempted_spend_height,
                attempted_spend_tombstone,
                token_id: *Mob::ID,
            }
        };

        let outlay = {
            let public_addr = AccountKey::random(&mut rng).default_subaddress();
            OutlayV2 {
                receiver: public_addr,
                amount: Amount::new(1234, TokenId::from(0)),
            }
        };

        let outlay_index_to_tx_out_index = HashMap::from_iter(vec![(0, 0)]);
        let outlay_confirmation_numbers = vec![TxOutConfirmationNumber::from([0u8; 32])];

        // Rust -> Proto
        let rust = TxProposal {
            utxos: vec![utxo],
            outlays: vec![outlay],
            tx,
            outlay_index_to_tx_out_index,
            outlay_confirmation_numbers,
            scis: vec![],
        };

        let proto = api::TxProposal::from(&rust);

        assert_eq!(
            rust.utxos,
            vec![UnspentTxOut::try_from(&proto.get_input_list()[0]).unwrap()],
        );

        assert_eq!(
            rust.outlays,
            vec![OutlayV2::try_from(&proto.get_outlay_list()[0]).unwrap()],
        );

        assert_eq!(proto.get_outlay_index_to_tx_out_index().len(), 1);
        assert_eq!(proto.get_outlay_index_to_tx_out_index().get(&0), Some(&0));

        assert_eq!(rust.tx, Tx::try_from(proto.get_tx()).unwrap());

        // Proto -> Rust
        assert_eq!(rust, TxProposal::try_from(&proto).unwrap());
    }
}
