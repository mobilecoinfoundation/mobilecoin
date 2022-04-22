// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Defines an object for each known high-level memo type,
//! and an enum to allow matching recovered memos to one of these types.
//!
//! The framework for memo types was proposed for standardization
//! in mobilecoinfoundation/mcips/pull/3.
//!
//! Several memo types from that proposal and subsequent proposals
//! are implemented in modules beneath this module, and then included in the
//! MemoType enum defined in this module.
//!
//! The intended use is like:
//! - Call `TxOut::decrypt_memo`, obtaining `MemoPayload`
//! - Call `MemoType::try_from`, obtaining the enum `MemoType`
//! - Match on the enum, which tells you what memo type this is, then you can
//!   read that data and validate it. See individual memo types for their
//!   semantics.
//!
//! To add a new memo type, you can add it to this crate in a new module,
//! make it implement `RegisteredMemoType`, and add it to the `impl_memo_enum`
//! macro call below.
//!
//! You can also make your own custom version of `MemoType` using different
//! structs, in your own crate, if you prefer. The `impl_memo_enum` macro is
//! exported, and will work as long as your memo types all implement
//! RegisteredMemoType, and all have different MEMO_TYPE_BYTES.
//!
//! If you want to put new memo types into transactions, you will need to
//! implement a new `MemoBuilder`. See the `memo_builder` module for examples.
//! Or, if you don't want to use the `TransactionBuilder`, you can call
//! `TxOut::new_with_memo` directly.

use crate::impl_memo_enum;
use core::{convert::TryFrom, fmt::Debug};
use displaydoc::Display;

mod authenticated_common;
mod authenticated_sender;
mod authenticated_sender_with_payment_request_id;
mod credential;
mod destination;
mod macros;
mod unused;

pub use authenticated_common::compute_category1_hmac;
pub use authenticated_sender::AuthenticatedSenderMemo;
pub use authenticated_sender_with_payment_request_id::AuthenticatedSenderWithPaymentRequestIdMemo;
pub use credential::SenderMemoCredential;
pub use destination::{DestinationMemo, DestinationMemoError};
pub use unused::UnusedMemo;

/// A trait that all registered memo types should implement.
/// This creates a single source of truth for the memo type bytes.
pub trait RegisteredMemoType:
    Sized + Clone + Debug + Into<[u8; 64]> + for<'a> From<&'a [u8; 64]>
{
    /// The type bytes assigned to this memo type.
    /// These are typically found in the MCIP that specifies this memo type.
    ///
    /// The first byte is conceptually a "type category"
    /// The second byte is a type within the category
    const MEMO_TYPE_BYTES: [u8; 2];
}

/// An error that can occur when trying to interpret a raw MemoPayload as
/// a MemoType
#[derive(Clone, Display, Debug)]
pub enum MemoDecodingError {
    /// Unknown memo type: type bytes were {0:02X?}
    UnknownMemoType([u8; 2]),
}

impl_memo_enum! { MemoType,
    Unused(UnusedMemo),
    AuthenticatedSender(AuthenticatedSenderMemo),
    AuthenticatedSenderWithPaymentRequestId(AuthenticatedSenderWithPaymentRequestIdMemo),
    Destination(DestinationMemo),
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::{AccountKey, ShortAddressHash};
    use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate};
    use mc_transaction_core::MemoPayload;
    use mc_util_from_random::FromRandom;
    use mc_util_serial;
    use rand::{rngs::StdRng, SeedableRng};
    use std::convert::TryInto;

    #[test]
    fn test_java_memo() {
        let alice_bytes : [u8; 657]= hex::decode(&"0a220a20ec8cb9814ac5c1a4aacbc613e756744679050927cc9e5f8772c6d649d4a5ac0612220a20e7ef0b2772663314ecd7ee92008613764ab5669666d95bd2621d99d60506cb0d1a1e666f673a2f2f666f672e616c7068612e6d6f62696c65636f696e2e636f6d2aa60430820222300d06092a864886f70d01010105000382020f003082020a0282020100c853a8724bc211cf5370ed4dbec8947c5573bed0ec47ae14211454977b41336061f0a040f77dbf529f3a46d8095676ec971b940ab4c9642578760779840a3f9b3b893b2f65006c544e9c16586d33649769b7c1c94552d7efa081a56ad612dec932812676ebec091f2aed69123604f4888a125e04ff85f5a727c286664378581cf34c7ee13eb01cc4faf3308ed3c07a9415f98e5fbfe073e6c357967244e46ba6ebbe391d8154e6e4a1c80524b1a6733eca46e37bfdd62d75816988a79aac6bdb62a06b1237a8ff5e5c848d01bbff684248cf06d92f301623c893eb0fba0f3faee2d197ea57ac428f89d6c000f76d58d5aacc3d70204781aca45bc02b1456b454231d2f2ed4ca6614e5242c7d7af0fe61e9af6ecfa76674ffbc29b858091cbfb4011538f0e894ce45d21d7fac04ba2ff57e9ff6db21e2afd9468ad785c262ec59d4a1a801c5ec2f95fc107dc9cb5f7869d70aa84450b8c350c2fa48bddef20752a1e43676b246c7f59f8f1f4aee43c1a15f36f7a36a9ec708320ea42089991551f2656ec62ea38233946b85616ff182cf17cd227e596329b546ea04d13b053be4cf3338de777b50bc6eca7a6185cf7a5022bc9be3749b1bb43e10ecc88a0c580f2b7373138ee49c7bafd8be6a64048887230480b0c85a045255494e04a9a81646369ce7a10e08da6fae27333ec0c16c8a74d93779a9e055395078d0b07286f9930203010001").unwrap().try_into().unwrap();
        let alice: AccountKey = mc_util_serial::decode(&alice_bytes).unwrap();

        let bob_bytes : [u8; 657]= hex::decode(&"0a220a20553a1c51c1e91d3105b17c909c163f8bc6faf93718deb06e5b9fdb9a24c2560912220a20db8b25545216d606fc3ff6da43d3281e862ba254193aff8c408f3564aefca5061a1e666f673a2f2f666f672e616c7068612e6d6f62696c65636f696e2e636f6d2aa60430820222300d06092a864886f70d01010105000382020f003082020a0282020100c853a8724bc211cf5370ed4dbec8947c5573bed0ec47ae14211454977b41336061f0a040f77dbf529f3a46d8095676ec971b940ab4c9642578760779840a3f9b3b893b2f65006c544e9c16586d33649769b7c1c94552d7efa081a56ad612dec932812676ebec091f2aed69123604f4888a125e04ff85f5a727c286664378581cf34c7ee13eb01cc4faf3308ed3c07a9415f98e5fbfe073e6c357967244e46ba6ebbe391d8154e6e4a1c80524b1a6733eca46e37bfdd62d75816988a79aac6bdb62a06b1237a8ff5e5c848d01bbff684248cf06d92f301623c893eb0fba0f3faee2d197ea57ac428f89d6c000f76d58d5aacc3d70204781aca45bc02b1456b454231d2f2ed4ca6614e5242c7d7af0fe61e9af6ecfa76674ffbc29b858091cbfb4011538f0e894ce45d21d7fac04ba2ff57e9ff6db21e2afd9468ad785c262ec59d4a1a801c5ec2f95fc107dc9cb5f7869d70aa84450b8c350c2fa48bddef20752a1e43676b246c7f59f8f1f4aee43c1a15f36f7a36a9ec708320ea42089991551f2656ec62ea38233946b85616ff182cf17cd227e596329b546ea04d13b053be4cf3338de777b50bc6eca7a6185cf7a5022bc9be3749b1bb43e10ecc88a0c580f2b7373138ee49c7bafd8be6a64048887230480b0c85a045255494e04a9a81646369ce7a10e08da6fae27333ec0c16c8a74d93779a9e055395078d0b07286f9930203010001").unwrap().try_into().unwrap();
        let bob: AccountKey = mc_util_serial::decode(&bob_bytes).unwrap();

        let tx_public_key_bytes: [u8; 32] =
            hex::decode(&"c235c13c4dedd808e95f428036716d52561fad7f51ce675f4d4c9c1fa1ea2165")
                .unwrap()
                .try_into()
                .unwrap();
        let tx_public_key = CompressedRistrettoPublic::from(&tx_public_key_bytes);

        let alice_cred = SenderMemoCredential::from(&alice);
        let memo = AuthenticatedSenderMemo::new(
            &alice_cred,
            bob.default_subaddress().view_public_key(),
            &tx_public_key,
        );
        let memo_bytes: [u8; 64] = memo.clone().into();

        let result = memo.validate(
            &alice.default_subaddress(),
            &bob.default_subaddress_view_private(),
            &tx_public_key,
        );
        println!("Memo payload:  is: {}", hex::encode(memo_bytes));
        println!("Result is: {}", result.unwrap_u8());
    }

    #[test]
    fn test_memo_type_round_trips() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let alice = AccountKey::new(
            &RistrettoPrivate::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
        );
        let alice_cred = SenderMemoCredential::from(&alice);

        let bob = AccountKey::new(
            &RistrettoPrivate::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
        );
        let bob_addr = bob.default_subaddress();

        let tx_public_key = CompressedRistrettoPublic::from_random(&mut rng);

        let memo1 = UnusedMemo {};
        match MemoType::try_from(&MemoPayload::from(memo1)).unwrap() {
            MemoType::Unused(_) => {}
            _ => {
                panic!("unexpected deserialization");
            }
        }

        let memo2 =
            AuthenticatedSenderMemo::new(&alice_cred, bob_addr.view_public_key(), &tx_public_key);
        match MemoType::try_from(&MemoPayload::from(memo2.clone())).unwrap() {
            MemoType::AuthenticatedSender(memo) => {
                assert_eq!(memo2, memo, "memo did not round trip");
            }
            _ => {
                panic!("unexpected deserialization");
            }
        }

        let memo3 = AuthenticatedSenderWithPaymentRequestIdMemo::new(
            &alice_cred,
            bob_addr.view_public_key(),
            &tx_public_key,
            7u64,
        );
        match MemoType::try_from(&MemoPayload::from(memo3.clone())).unwrap() {
            MemoType::AuthenticatedSenderWithPaymentRequestId(memo) => {
                assert_eq!(memo3, memo);
            }
            _ => {
                panic!("unexpected deserialization");
            }
        }

        let memo4 = DestinationMemo::new(ShortAddressHash::from(&bob_addr), 17, 18).unwrap();
        match MemoType::try_from(&MemoPayload::from(memo4.clone())).unwrap() {
            MemoType::Destination(memo) => {
                assert_eq!(memo4, memo);
            }
            _ => {
                panic!("unexpected deserialization");
            }
        }

        let memo5 = MemoPayload::new([7u8, 8u8], [0u8; 64]);
        match MemoType::try_from(&memo5) {
            Ok(_) => {
                panic!("failure was expected");
            }
            Err(err) => match err {
                MemoDecodingError::UnknownMemoType(code) => {
                    assert_eq!(code, [7u8, 8u8], "unexpected memo type bytes");
                }
            },
        }
    }

    #[test]
    fn test_memo_authentication() {
        let mut rng: StdRng = SeedableRng::from_seed([2u8; 32]);

        let alice = AccountKey::new(
            &RistrettoPrivate::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
        );
        let alice_cred = SenderMemoCredential::from(&alice);
        let alice_addr = alice.default_subaddress();

        let bob = AccountKey::new(
            &RistrettoPrivate::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
        );
        let bob_addr = bob.default_subaddress();

        let tx_public_key = CompressedRistrettoPublic::from_random(&mut rng);
        let tx_public_key2 = CompressedRistrettoPublic::from_random(&mut rng);

        let memo1 =
            AuthenticatedSenderMemo::new(&alice_cred, bob_addr.view_public_key(), &tx_public_key);
        assert_eq!(
            memo1.sender_address_hash(),
            ShortAddressHash::from(&alice_addr)
        );
        assert!(
            bool::from(memo1.validate(
                &alice_addr,
                &bob.default_subaddress_view_private(),
                &tx_public_key
            )),
            "validation should have passed"
        );
        assert!(
            !bool::from(memo1.validate(
                &bob_addr,
                &bob.default_subaddress_view_private(),
                &tx_public_key
            )),
            "validation should have failed"
        );
        assert!(
            !bool::from(memo1.validate(
                &alice_addr,
                &alice.default_subaddress_view_private(),
                &tx_public_key
            )),
            "validation should have failed"
        );
        assert!(
            !bool::from(memo1.validate(
                &bob_addr,
                &alice.default_subaddress_view_private(),
                &tx_public_key
            )),
            "validation should have failed"
        );
        assert!(
            !bool::from(memo1.validate(
                &alice_addr,
                &bob.default_subaddress_view_private(),
                &tx_public_key2
            )),
            "validation should have failed"
        );
        assert!(
            !bool::from(memo1.validate(
                &bob_addr,
                &bob.default_subaddress_view_private(),
                &tx_public_key2
            )),
            "validation should have failed"
        );
        assert!(
            !bool::from(memo1.validate(
                &alice_addr,
                &alice.default_subaddress_view_private(),
                &tx_public_key2
            )),
            "validation should have failed"
        );
        assert!(
            !bool::from(memo1.validate(
                &bob_addr,
                &alice.default_subaddress_view_private(),
                &tx_public_key2
            )),
            "validation should have failed"
        );

        let memo2 = AuthenticatedSenderWithPaymentRequestIdMemo::new(
            &alice_cred,
            bob_addr.view_public_key(),
            &tx_public_key,
            7u64,
        );
        assert_eq!(
            memo2.sender_address_hash(),
            ShortAddressHash::from(&alice_addr)
        );
        assert_eq!(memo2.payment_request_id(), 7u64);
        assert!(
            bool::from(memo2.validate(
                &alice_addr,
                &bob.default_subaddress_view_private(),
                &tx_public_key
            )),
            "validation should have passed"
        );
        assert!(
            !bool::from(memo2.validate(
                &bob_addr,
                &bob.default_subaddress_view_private(),
                &tx_public_key
            )),
            "validation should have failed"
        );
        assert!(
            !bool::from(memo2.validate(
                &alice_addr,
                &alice.default_subaddress_view_private(),
                &tx_public_key
            )),
            "validation should have failed"
        );
        assert!(
            !bool::from(memo2.validate(
                &bob_addr,
                &alice.default_subaddress_view_private(),
                &tx_public_key
            )),
            "validation should have failed"
        );
        assert!(
            !bool::from(memo2.validate(
                &alice_addr,
                &bob.default_subaddress_view_private(),
                &tx_public_key2
            )),
            "validation should have failed"
        );
        assert!(
            !bool::from(memo2.validate(
                &bob_addr,
                &bob.default_subaddress_view_private(),
                &tx_public_key2
            )),
            "validation should have failed"
        );
        assert!(
            !bool::from(memo2.validate(
                &alice_addr,
                &alice.default_subaddress_view_private(),
                &tx_public_key2
            )),
            "validation should have failed"
        );
        assert!(
            !bool::from(memo2.validate(
                &bob_addr,
                &alice.default_subaddress_view_private(),
                &tx_public_key2
            )),
            "validation should have failed"
        );
    }

    #[test]
    fn test_destination_memo() {
        let mut rng: StdRng = SeedableRng::from_seed([2u8; 32]);

        let alice = AccountKey::new(
            &RistrettoPrivate::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
        );
        let alice_addr = alice.default_subaddress();

        let bob = AccountKey::new(
            &RistrettoPrivate::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
        );
        let bob_addr = bob.default_subaddress();

        let mut memo =
            DestinationMemo::new(ShortAddressHash::from(&alice_addr), 12u64, 13u64).unwrap();

        assert_eq!(
            memo.get_address_hash(),
            &ShortAddressHash::from(&alice_addr)
        );
        assert_eq!(memo.get_total_outlay(), 12u64);
        assert_eq!(memo.get_fee(), 13u64);
        assert_eq!(memo.get_num_recipients(), 1);

        memo.set_address_hash(ShortAddressHash::from(&bob_addr));
        memo.set_total_outlay(19);
        memo.set_fee(17).unwrap();
        memo.set_num_recipients(4);

        assert_eq!(memo.get_address_hash(), &ShortAddressHash::from(&bob_addr));
        assert_eq!(memo.get_total_outlay(), 19u64);
        assert_eq!(memo.get_fee(), 17u64);
        assert_eq!(memo.get_num_recipients(), 4);
    }
}
