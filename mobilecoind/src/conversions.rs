// Copyright (c) 2018-2024 The MobileCoin Foundation

//! Utilities for converting between `mobilecoind` and `mobilecoind_api` data
//! types.

use crate::{
    payments::{Outlay, OutlayV2, SciForTx, TxProposal},
    utxo_store::UnspentTxOut,
};
use mc_account_keys::PublicAddress;
use mc_api::ConversionError;
use mc_common::HashMap;
use mc_crypto_keys::RistrettoPrivate;
use mc_mobilecoind_api as api;
use mc_transaction_core::{
    ring_signature::KeyImage,
    tx::{Tx, TxOut},
    Amount, MemoPayload, TokenId,
};
use mc_transaction_extra::{MemoType, TxOutConfirmationNumber};

impl From<&UnspentTxOut> for api::UnspentTxOut {
    fn from(src: &UnspentTxOut) -> Self {
        Self {
            tx_out: Some((&src.tx_out).into()),
            subaddress_index: src.subaddress_index,
            key_image: Some((&src.key_image).into()),
            value: src.value,
            attempted_spend_height: src.attempted_spend_height,
            attempted_spend_tombstone: src.attempted_spend_tombstone,
            token_id: src.token_id,
            memo_payload: src.memo_payload.clone(),
            decoded_memo: MemoPayload::try_from(&src.memo_payload[..])
                .ok()
                .map(|m| decode_memo(&m)),
            ..Default::default()
        }
    }
}

impl TryFrom<&api::UnspentTxOut> for UnspentTxOut {
    type Error = ConversionError;

    fn try_from(src: &api::UnspentTxOut) -> Result<Self, Self::Error> {
        let tx_out = TxOut::try_from(src.tx_out.as_ref().unwrap_or(&Default::default()))?;
        let subaddress_index = src.subaddress_index;
        let key_image = KeyImage::try_from(src.key_image.as_ref().unwrap_or(&Default::default()))?;
        let value = src.value;
        let attempted_spend_height = src.attempted_spend_height;
        let attempted_spend_tombstone = src.attempted_spend_tombstone;
        let token_id = src.token_id;
        let memo_payload = src.memo_payload.clone();

        Ok(Self {
            tx_out,
            subaddress_index,
            key_image,
            value,
            attempted_spend_height,
            attempted_spend_tombstone,
            token_id,
            memo_payload,
        })
    }
}

fn bytes_to_tx_private_key(bytes: &[u8]) -> Result<Option<RistrettoPrivate>, ConversionError> {
    if bytes.is_empty() {
        return Ok(None);
    }

    let bytes = <&[u8; 32] as TryFrom<&[u8]>>::try_from(bytes)?;
    Ok(Some(RistrettoPrivate::from_bytes_mod_order(bytes)))
}

// Convert an arbitrary MemoPayload to the api::DecodedMemo format.
// When this fails, it sets the UnknownMemo variant in the result.
//
// Note: This could be From<&MemoPayload> for api::DecodedMemo, but there are
// orphan rules issues.
fn decode_memo(memo_payload: &MemoPayload) -> api::DecodedMemo {
    let mut result = api::DecodedMemo::default();

    match MemoType::try_from(memo_payload) {
        Ok(MemoType::Unused(_)) => {}
        Ok(MemoType::AuthenticatedSender(memo)) => {
            let asm = api::AuthenticatedSenderMemo {
                sender_hash: memo.sender_address_hash().as_ref().to_vec(),
                ..Default::default()
            };
            result.decoded_memo =
                Some(api::decoded_memo::DecodedMemo::AuthenticatedSenderMemo(asm));
        }
        Ok(MemoType::AuthenticatedSenderWithPaymentRequestId(memo)) => {
            let asm = api::AuthenticatedSenderMemo {
                sender_hash: memo.sender_address_hash().as_ref().to_vec(),
                payment_request_id: Some(memo.payment_request_id()),
                ..Default::default()
            };
            result.decoded_memo =
                Some(api::decoded_memo::DecodedMemo::AuthenticatedSenderMemo(asm));
        }
        Ok(MemoType::AuthenticatedSenderWithPaymentIntentId(memo)) => {
            let asm = api::AuthenticatedSenderMemo {
                sender_hash: memo.sender_address_hash().as_ref().to_vec(),
                payment_intent_id: Some(memo.payment_intent_id()),
                ..Default::default()
            };
            result.decoded_memo =
                Some(api::decoded_memo::DecodedMemo::AuthenticatedSenderMemo(asm));
        }
        Ok(_) | Err(_) => {
            let um = api::UnknownMemo {
                type_bytes: memo_payload.get_memo_type().to_vec(),
            };
            result.decoded_memo = Some(api::decoded_memo::DecodedMemo::UnknownMemo(um));
        }
    }

    result
}

impl From<&Outlay> for api::Outlay {
    fn from(src: &Outlay) -> Self {
        Self {
            value: src.value,
            receiver: Some((&src.receiver).into()),
            tx_private_key: src
                .tx_private_key
                .map(|k| k.to_bytes().to_vec())
                .unwrap_or_default(),
        }
    }
}

impl TryFrom<&api::Outlay> for Outlay {
    type Error = ConversionError;

    fn try_from(src: &api::Outlay) -> Result<Self, Self::Error> {
        let value = src.value;
        let receiver =
            PublicAddress::try_from(src.receiver.as_ref().unwrap_or(&Default::default()))?;
        let tx_private_key = bytes_to_tx_private_key(src.tx_private_key.as_slice())?;

        Ok(Self {
            value,
            receiver,
            tx_private_key,
        })
    }
}

impl From<&OutlayV2> for api::OutlayV2 {
    fn from(src: &OutlayV2) -> Self {
        Self {
            value: src.amount.value,
            token_id: *src.amount.token_id,
            receiver: Some((&src.receiver).into()),
            tx_private_key: src
                .tx_private_key
                .map(|k| k.to_bytes().to_vec())
                .unwrap_or_default(),
        }
    }
}

impl TryFrom<&api::OutlayV2> for OutlayV2 {
    type Error = ConversionError;

    fn try_from(src: &api::OutlayV2) -> Result<Self, Self::Error> {
        let amount = Amount::new(src.value, TokenId::from(src.token_id));
        let receiver =
            PublicAddress::try_from(src.receiver.as_ref().unwrap_or(&Default::default()))?;
        let tx_private_key = bytes_to_tx_private_key(src.tx_private_key.as_slice())?;

        Ok(Self {
            amount,
            receiver,
            tx_private_key,
        })
    }
}

impl From<&TxProposal> for api::TxProposal {
    fn from(src: &TxProposal) -> api::TxProposal {
        Self {
            input_list: src.utxos.iter().map(Into::into).collect(),
            outlay_list: src.outlays.iter().map(Into::into).collect(),
            tx: Some((&src.tx).into()),
            fee: src.tx.prefix.fee,
            outlay_index_to_tx_out_index: src
                .outlay_index_to_tx_out_index
                .iter()
                .map(|(key, val)| (*key as u64, *val as u64))
                .collect(),
            outlay_confirmation_numbers: src
                .outlay_confirmation_numbers
                .iter()
                .map(|val| val.to_vec())
                .collect(),
            scis: src.scis.iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<&api::TxProposal> for TxProposal {
    type Error = ConversionError;

    fn try_from(src: &api::TxProposal) -> Result<Self, Self::Error> {
        if src.fee
            != src
                .tx
                .as_ref()
                .unwrap_or(&Default::default())
                .prefix
                .as_ref()
                .unwrap_or(&Default::default())
                .fee
        {
            return Err(ConversionError::FeeMismatch);
        }

        let utxos = src
            .input_list
            .iter()
            .map(UnspentTxOut::try_from)
            .collect::<Result<Vec<UnspentTxOut>, ConversionError>>()?;

        let outlays: Vec<OutlayV2> = src
            .outlay_list
            .iter()
            .map(OutlayV2::try_from)
            .collect::<Result<_, _>>()?;

        let scis: Vec<SciForTx> = src
            .scis
            .iter()
            .map(SciForTx::try_from)
            .collect::<Result<_, _>>()?;

        let tx = Tx::try_from(src.tx.as_ref().unwrap_or(&Default::default()))?;

        let outlay_index_to_tx_out_index = src
            .outlay_index_to_tx_out_index
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
            .outlay_confirmation_numbers
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
        Self {
            sci: Some((&src.sci).into()),
            partial_fill_value: src.partial_fill_value,
        }
    }
}

impl TryFrom<&api::SciForTx> for SciForTx {
    type Error = ConversionError;

    fn try_from(src: &api::SciForTx) -> Result<Self, Self::Error> {
        let sci = src.sci.as_ref().unwrap_or(&Default::default()).try_into()?;
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
    use mc_account_keys::{AccountKey, ShortAddressHash};
    use mc_crypto_keys::CompressedRistrettoPublic;
    use mc_ledger_db::{
        test_utils::{create_ledger, create_transaction, initialize_ledger},
        Ledger,
    };
    use mc_mobilecoind_api::decoded_memo;
    use mc_transaction_core::{tokens::Mob, BlockVersion, Token};
    use mc_transaction_extra::{
        AuthenticatedSenderMemo, AuthenticatedSenderWithPaymentIntentIdMemo,
        AuthenticatedSenderWithPaymentRequestIdMemo, DestinationMemo, SenderMemoCredential,
        UnusedMemo,
    };
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
            memo_payload: vec![6u8, 66],
        };

        let proto = api::UnspentTxOut::from(&rust);

        assert_eq!(
            tx_out,
            TxOut::try_from(proto.tx_out.as_ref().unwrap()).unwrap()
        );
        assert_eq!(subaddress_index, proto.subaddress_index);
        assert_eq!(
            key_image,
            KeyImage::try_from(proto.key_image.as_ref().unwrap()).unwrap()
        );
        assert_eq!(value, proto.value);
        assert_eq!(attempted_spend_height, proto.attempted_spend_height);
        assert_eq!(attempted_spend_tombstone, proto.attempted_spend_tombstone);

        // Proto -> Rust
        assert_eq!(rust, UnspentTxOut::try_from(&proto).unwrap());
    }

    // Test the decode_memo implementation
    #[test]
    fn test_memo_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let alice = AccountKey::new(
            &RistrettoPrivate::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
        );
        let alice_cred = SenderMemoCredential::from(&alice);
        let alice_hash = alice_cred.address_hash;

        let bob = AccountKey::new(
            &RistrettoPrivate::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
        );
        let bob_addr = bob.default_subaddress();

        let tx_public_key = CompressedRistrettoPublic::from_random(&mut rng);

        let memo1 = UnusedMemo {};
        let decoded = decode_memo(&MemoPayload::from(memo1));
        assert_eq!(decoded.decoded_memo, None);

        let memo2 =
            AuthenticatedSenderMemo::new(&alice_cred, bob_addr.view_public_key(), &tx_public_key)
                .unwrap();
        let decoded = decode_memo(&MemoPayload::from(memo2));
        if let Some(decoded_memo::DecodedMemo::AuthenticatedSenderMemo(memo)) = decoded.decoded_memo
        {
            assert_eq!(memo.sender_hash, alice_hash.as_ref());
            assert_eq!(memo.payment_request_id, None);
            assert_eq!(memo.payment_intent_id, None);
        } else {
            panic!("Expected AuthenticatedSenderMemo, got {decoded:?}");
        }

        let memo3 = AuthenticatedSenderWithPaymentRequestIdMemo::new(
            &alice_cred,
            bob_addr.view_public_key(),
            &tx_public_key,
            7u64,
        )
        .unwrap();
        let decoded = decode_memo(&MemoPayload::from(memo3));
        if let Some(decoded_memo::DecodedMemo::AuthenticatedSenderMemo(memo)) = decoded.decoded_memo
        {
            assert_eq!(memo.sender_hash, alice_hash.as_ref());
            assert_eq!(memo.payment_request_id, Some(7));
            assert_eq!(memo.payment_intent_id, None);
        } else {
            panic!("Expected AuthenticatedSenderMemo, got {decoded:?}");
        }

        let memo4 = AuthenticatedSenderWithPaymentIntentIdMemo::new(
            &alice_cred,
            bob_addr.view_public_key(),
            &tx_public_key,
            9u64,
        )
        .unwrap();
        let decoded = decode_memo(&MemoPayload::from(memo4));
        if let Some(decoded_memo::DecodedMemo::AuthenticatedSenderMemo(memo)) = decoded.decoded_memo
        {
            assert_eq!(memo.sender_hash, alice_hash.as_ref());
            assert_eq!(memo.payment_request_id, None);
            assert_eq!(memo.payment_intent_id, Some(9));
        } else {
            panic!("Expected AuthenticatedSenderMemo, got {decoded:?}");
        }

        // Destination memos are not implemented yet
        let memo5 = DestinationMemo::new(ShortAddressHash::from(&bob_addr), 17, 18).unwrap();
        let decoded = decode_memo(&MemoPayload::from(memo5));
        if let Some(decoded_memo::DecodedMemo::UnknownMemo(memo)) = decoded.decoded_memo {
            assert_eq!(memo.type_bytes, &[2u8, 0u8]);
        } else {
            panic!("Expected UnknownMemo, got {decoded:?}");
        }

        // This is an unassigned memo type
        let memo6 = MemoPayload::new([7u8, 8u8], [0u8; 64]);
        let decoded = decode_memo(&memo6);
        if let Some(decoded_memo::DecodedMemo::UnknownMemo(memo)) = decoded.decoded_memo {
            assert_eq!(memo.type_bytes, &[7u8, 8u8]);
        } else {
            panic!("Expected UnknownMemo, got {decoded:?}");
        }
    }

    #[test]
    fn test_outlay_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let public_addr = AccountKey::random(&mut rng).default_subaddress();

        // Rust -> Proto
        let rust = Outlay {
            receiver: public_addr.clone(),
            value: 1234,
            tx_private_key: None,
        };
        let proto = api::Outlay::from(&rust);

        assert_eq!(proto.value, rust.value);
        assert_eq!(
            PublicAddress::try_from(proto.receiver.as_ref().unwrap()).unwrap(),
            public_addr
        );

        // Proto -> Rust
        assert_eq!(rust, Outlay::try_from(&proto).unwrap());
    }

    #[test]
    fn test_outlay_conversion_with_tx_private_key() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let public_addr = AccountKey::random(&mut rng).default_subaddress();

        // Rust -> Proto, with tx private key
        let rust = Outlay {
            receiver: public_addr.clone(),
            value: 1234,
            tx_private_key: Some(RistrettoPrivate::from_random(&mut rng)),
        };
        let proto = api::Outlay::from(&rust);

        assert_eq!(proto.value, rust.value);
        assert_eq!(
            PublicAddress::try_from(proto.receiver.as_ref().unwrap()).unwrap(),
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
                &ledger,
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
                memo_payload: vec![9u8, 66],
            }
        };

        let outlay = {
            let public_addr = AccountKey::random(&mut rng).default_subaddress();
            OutlayV2 {
                receiver: public_addr,
                amount: Amount::new(1234, TokenId::from(0)),
                tx_private_key: Some(RistrettoPrivate::from_random(&mut rng)),
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
            vec![UnspentTxOut::try_from(&proto.input_list[0]).unwrap()],
        );

        assert_eq!(
            rust.outlays,
            vec![OutlayV2::try_from(&proto.outlay_list[0]).unwrap()],
        );

        assert_eq!(proto.outlay_index_to_tx_out_index.len(), 1);
        assert_eq!(proto.outlay_index_to_tx_out_index.get(&0), Some(&0));

        assert_eq!(rust.tx, Tx::try_from(proto.tx.as_ref().unwrap()).unwrap());

        // Proto -> Rust
        assert_eq!(rust, TxProposal::try_from(&proto).unwrap());
    }
}
