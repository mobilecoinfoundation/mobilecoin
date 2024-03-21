// Copyright (c) 2018-2024 The MobileCoin Foundation

use mc_account_keys::AccountKey;
use mc_api::ConversionError;
use mc_mobilecoind_api::{
    mobilecoind_api, TransactionMemo_RTH_oneof_payment_id, TransactionMemo_oneof_transaction_memo,
};
use mc_transaction_builder::{
    BurnRedemptionMemoBuilder, EmptyMemoBuilder, MemoBuilder, RTHMemoBuilder,
};
use mc_transaction_extra::{BurnRedemptionMemo, SenderMemoCredential};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionMemo {
    /// Recoverable Transaction History memo with an optional u64 specifying the
    /// subaddress index to generate the sender memo credential from
    RTH {
        /// Optional subaddress index to generate the sender memo credential
        /// from.
        subaddress_index: Option<u64>,
    },

    RTHWithPaymentIntentId {
        /// Optional subaddress index to generate the sender memo credential
        /// from.
        subaddress_index: Option<u64>,

        /// The payment intent id to include in the memo.
        payment_intent_id: u64,
    },

    RTHWithPaymentRequestId {
        /// Optional subaddress index to generate the sender memo credential
        /// from.
        subaddress_index: Option<u64>,

        /// The payment request id to include in the memo.
        payment_request_id: u64,
    },

    /// Empty Transaction Memo.
    Empty,

    /// Burn Redemption memo.
    BurnRedemption([u8; BurnRedemptionMemo::MEMO_DATA_LEN]),
}

impl TransactionMemo {
    pub fn memo_builder(&self, account_key: &AccountKey) -> Box<dyn MemoBuilder + Send + Sync> {
        match self {
            Self::Empty => Box::<EmptyMemoBuilder>::default(),
            Self::RTH { subaddress_index } => {
                let memo_builder = generate_rth_memo_builder(subaddress_index, account_key);
                Box::new(memo_builder)
            }
            Self::RTHWithPaymentIntentId {
                subaddress_index,
                payment_intent_id,
            } => {
                let mut memo_builder = generate_rth_memo_builder(subaddress_index, account_key);
                memo_builder.set_payment_intent_id(*payment_intent_id);
                Box::new(memo_builder)
            }
            Self::RTHWithPaymentRequestId {
                subaddress_index,
                payment_request_id,
            } => {
                let mut memo_builder = generate_rth_memo_builder(subaddress_index, account_key);
                memo_builder.set_payment_request_id(*payment_request_id);
                Box::new(memo_builder)
            }
            Self::BurnRedemption(memo_data) => {
                let mut memo_builder = BurnRedemptionMemoBuilder::new(*memo_data);
                memo_builder.enable_destination_memo();
                Box::new(memo_builder)
            }
        }
    }
}

fn generate_rth_memo_builder(
    subaddress_index: &Option<u64>,
    account_key: &AccountKey,
) -> RTHMemoBuilder {
    let mut memo_builder = RTHMemoBuilder::default();
    let sender_memo_credential = match subaddress_index {
        Some(subaddress_index) => SenderMemoCredential::new_from_address_and_spend_private_key(
            &account_key.subaddress(*subaddress_index),
            account_key.subaddress_spend_private(*subaddress_index),
        ),
        None => SenderMemoCredential::from(account_key),
    };
    memo_builder.set_sender_credential(sender_memo_credential);
    memo_builder.enable_destination_memo();

    memo_builder
}

impl TryFrom<&mobilecoind_api::TransactionMemo> for TransactionMemo {
    type Error = ConversionError;

    fn try_from(src: &mobilecoind_api::TransactionMemo) -> Result<Self, Self::Error> {
        match src.transaction_memo.as_ref() {
            // Default to RTH memo if nothing is explicitly specified
            None => Ok(TransactionMemo::RTH {
                subaddress_index: None,
            }),

            Some(TransactionMemo_oneof_transaction_memo::rth(rth)) => {
                let subaddress_index = if rth.has_subaddress_index() {
                    Some(rth.get_subaddress_index())
                } else {
                    None
                };
                match rth.payment_id.as_ref() {
                    None => Ok(TransactionMemo::RTH { subaddress_index }),

                    Some(TransactionMemo_RTH_oneof_payment_id::payment_intent_id(
                        payment_intent_id,
                    )) => Ok(TransactionMemo::RTHWithPaymentIntentId {
                        subaddress_index,
                        payment_intent_id: *payment_intent_id,
                    }),

                    Some(TransactionMemo_RTH_oneof_payment_id::payment_request_id(
                        payment_request_id,
                    )) => Ok(TransactionMemo::RTHWithPaymentRequestId {
                        subaddress_index,
                        payment_request_id: *payment_request_id,
                    }),
                }
            }

            Some(TransactionMemo_oneof_transaction_memo::empty(_)) => Ok(TransactionMemo::Empty),

            Some(TransactionMemo_oneof_transaction_memo::burn_redemption(burn_redemption)) => {
                if burn_redemption.memo_data.len() != BurnRedemptionMemo::MEMO_DATA_LEN {
                    return Err(ConversionError::ArrayCastError);
                }
                let mut memo = [0u8; BurnRedemptionMemo::MEMO_DATA_LEN];
                memo.copy_from_slice(&burn_redemption.memo_data);
                Ok(TransactionMemo::BurnRedemption(memo))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_memo_try_from_nothing() {
        let src = mobilecoind_api::TransactionMemo::default();
        let result = super::TransactionMemo::try_from(&src).unwrap();
        assert_eq!(
            result,
            super::TransactionMemo::RTH {
                subaddress_index: None
            }
        );
    }

    #[test]
    fn transaction_memo_try_from_rth_default() {
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(TransactionMemo_oneof_transaction_memo::rth(
                mc_mobilecoind_api::TransactionMemo_RTH::default(),
            )),
            ..Default::default()
        };
        let result = super::TransactionMemo::try_from(&src).unwrap();
        assert_eq!(
            result,
            super::TransactionMemo::RTH {
                subaddress_index: None
            }
        );
    }

    #[test]
    fn transaction_memo_try_from_rth_explicit_subaddress_index() {
        for subaddress_index in [0, 123, u64::MAX] {
            let mut rth = mc_mobilecoind_api::TransactionMemo_RTH::default();
            rth.set_subaddress_index(subaddress_index);
            let src = mobilecoind_api::TransactionMemo {
                transaction_memo: Some(TransactionMemo_oneof_transaction_memo::rth(rth)),
                ..Default::default()
            };

            let result = super::TransactionMemo::try_from(&src).unwrap();
            assert_eq!(
                result,
                super::TransactionMemo::RTH {
                    subaddress_index: Some(subaddress_index),
                }
            );
        }
    }

    #[test]
    fn transaction_memo_try_from_rth_payment_request_id() {
        let mut rth = mc_mobilecoind_api::TransactionMemo_RTH::default();
        rth.set_payment_request_id(123);
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(TransactionMemo_oneof_transaction_memo::rth(rth.clone())),
            ..Default::default()
        };

        let result = super::TransactionMemo::try_from(&src).unwrap();
        assert_eq!(
            result,
            super::TransactionMemo::RTHWithPaymentRequestId {
                subaddress_index: None,
                payment_request_id: 123,
            }
        );

        rth.set_subaddress_index(456);
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(TransactionMemo_oneof_transaction_memo::rth(rth)),
            ..Default::default()
        };

        let result = super::TransactionMemo::try_from(&src).unwrap();
        assert_eq!(
            result,
            super::TransactionMemo::RTHWithPaymentRequestId {
                subaddress_index: Some(456),
                payment_request_id: 123,
            }
        );
    }

    #[test]
    fn transaction_memo_try_from_rth_payment_intent_id() {
        let mut rth = mc_mobilecoind_api::TransactionMemo_RTH::default();
        rth.set_payment_intent_id(123);
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(TransactionMemo_oneof_transaction_memo::rth(rth.clone())),
            ..Default::default()
        };

        let result = super::TransactionMemo::try_from(&src).unwrap();
        assert_eq!(
            result,
            super::TransactionMemo::RTHWithPaymentIntentId {
                subaddress_index: None,
                payment_intent_id: 123,
            }
        );

        rth.set_subaddress_index(456);
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(TransactionMemo_oneof_transaction_memo::rth(rth)),
            ..Default::default()
        };

        let result = super::TransactionMemo::try_from(&src).unwrap();
        assert_eq!(
            result,
            super::TransactionMemo::RTHWithPaymentIntentId {
                subaddress_index: Some(456),
                payment_intent_id: 123,
            }
        );
    }

    #[test]
    fn transaction_memo_try_from_empty() {
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(TransactionMemo_oneof_transaction_memo::empty(
                Default::default(),
            )),
            ..Default::default()
        };
        let result = super::TransactionMemo::try_from(&src).unwrap();
        assert_eq!(result, super::TransactionMemo::Empty);
    }

    #[test]
    fn transaction_memo_try_from_burn_redemption() {
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(TransactionMemo_oneof_transaction_memo::burn_redemption(
                Default::default(),
            )),
            ..Default::default()
        };
        let result = super::TransactionMemo::try_from(&src).unwrap_err();
        assert_eq!(result, ConversionError::ArrayCastError);

        let burn_redemption = mc_mobilecoind_api::TransactionMemo_BurnRedemption {
            memo_data: vec![],
            ..Default::default()
        };
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(TransactionMemo_oneof_transaction_memo::burn_redemption(
                burn_redemption,
            )),
            ..Default::default()
        };
        let result = super::TransactionMemo::try_from(&src).unwrap_err();
        assert_eq!(result, ConversionError::ArrayCastError);

        let burn_redemption = mc_mobilecoind_api::TransactionMemo_BurnRedemption {
            memo_data: vec![1; BurnRedemptionMemo::MEMO_DATA_LEN - 1],
            ..Default::default()
        };
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(TransactionMemo_oneof_transaction_memo::burn_redemption(
                burn_redemption,
            )),
            ..Default::default()
        };
        let result = super::TransactionMemo::try_from(&src).unwrap_err();
        assert_eq!(result, ConversionError::ArrayCastError);

        let burn_redemption = mc_mobilecoind_api::TransactionMemo_BurnRedemption {
            memo_data: vec![1; BurnRedemptionMemo::MEMO_DATA_LEN],
            ..Default::default()
        };
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(TransactionMemo_oneof_transaction_memo::burn_redemption(
                burn_redemption,
            )),
            ..Default::default()
        };

        let result = super::TransactionMemo::try_from(&src).unwrap();
        assert_eq!(
            result,
            super::TransactionMemo::BurnRedemption([1; BurnRedemptionMemo::MEMO_DATA_LEN])
        );
    }
}
