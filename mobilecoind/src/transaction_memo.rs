// Copyright (c) 2018-2024 The MobileCoin Foundation

use mc_account_keys::AccountKey;
use mc_api::ConversionError;
use mc_mobilecoind_api::{mobilecoind_api, transaction_memo, transaction_memo_rth};
use mc_transaction_builder::{
    BurnRedemptionMemoBuilder, EmptyMemoBuilder, MemoBuilder, RTHMemoBuilder,
};
use mc_transaction_extra::{BurnRedemptionMemo, SenderMemoCredential};

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum TransactionMemo {
    /// Recoverable Transaction History memo with an optional u64 specifying the
    /// subaddress index to generate the sender memo credential from
    Rth {
        /// Optional subaddress index to generate the sender memo credential
        /// from.
        subaddress_index: Option<u64>,
    },

    RthWithPaymentIntentId {
        /// Optional subaddress index to generate the sender memo credential
        /// from.
        subaddress_index: Option<u64>,

        /// The payment intent id to include in the memo.
        payment_intent_id: u64,
    },

    RthWithPaymentRequestId {
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
            Self::Rth { subaddress_index } => {
                let memo_builder = generate_rth_memo_builder(subaddress_index, account_key);
                Box::new(memo_builder)
            }
            Self::RthWithPaymentIntentId {
                subaddress_index,
                payment_intent_id,
            } => {
                let mut memo_builder = generate_rth_memo_builder(subaddress_index, account_key);
                memo_builder.set_payment_intent_id(*payment_intent_id);
                Box::new(memo_builder)
            }
            Self::RthWithPaymentRequestId {
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
            None => Ok(TransactionMemo::Rth {
                subaddress_index: None,
            }),

            Some(transaction_memo::TransactionMemo::Rth(rth)) => {
                let subaddress_index = rth.subaddress_index;
                match rth.payment_id.as_ref() {
                    None => Ok(TransactionMemo::Rth { subaddress_index }),

                    Some(transaction_memo_rth::PaymentId::PaymentIntentId(payment_intent_id)) => {
                        Ok(TransactionMemo::RthWithPaymentIntentId {
                            subaddress_index,
                            payment_intent_id: *payment_intent_id,
                        })
                    }

                    Some(transaction_memo_rth::PaymentId::PaymentRequestId(payment_request_id)) => {
                        Ok(TransactionMemo::RthWithPaymentRequestId {
                            subaddress_index,
                            payment_request_id: *payment_request_id,
                        })
                    }
                }
            }

            Some(transaction_memo::TransactionMemo::Empty(_)) => Ok(TransactionMemo::Empty),

            Some(transaction_memo::TransactionMemo::BurnRedemption(burn_redemption)) => {
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
            super::TransactionMemo::Rth {
                subaddress_index: None
            }
        );
    }

    #[test]
    fn transaction_memo_try_from_rth_default() {
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(transaction_memo::TransactionMemo::Rth(Default::default())),
        };
        let result = super::TransactionMemo::try_from(&src).unwrap();
        assert_eq!(
            result,
            super::TransactionMemo::Rth {
                subaddress_index: None
            }
        );
    }

    #[test]
    fn transaction_memo_try_from_rth_explicit_subaddress_index() {
        for subaddress_index in [0, 123, u64::MAX] {
            let rth = mc_mobilecoind_api::TransactionMemoRth {
                subaddress_index: Some(subaddress_index),
                ..Default::default()
            };
            let src = mobilecoind_api::TransactionMemo {
                transaction_memo: Some(transaction_memo::TransactionMemo::Rth(rth)),
            };

            let result = super::TransactionMemo::try_from(&src).unwrap();
            assert_eq!(
                result,
                super::TransactionMemo::Rth {
                    subaddress_index: Some(subaddress_index),
                }
            );
        }
    }

    #[test]
    fn transaction_memo_try_from_rth_payment_request_id() {
        let mut rth = mc_mobilecoind_api::TransactionMemoRth {
            payment_id: Some(transaction_memo_rth::PaymentId::PaymentRequestId(123)),
            ..Default::default()
        };
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(transaction_memo::TransactionMemo::Rth(rth.clone())),
        };

        let result = super::TransactionMemo::try_from(&src).unwrap();
        assert_eq!(
            result,
            super::TransactionMemo::RthWithPaymentRequestId {
                subaddress_index: None,
                payment_request_id: 123,
            }
        );

        rth.subaddress_index = Some(456);
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(transaction_memo::TransactionMemo::Rth(rth)),
        };

        let result = super::TransactionMemo::try_from(&src).unwrap();
        assert_eq!(
            result,
            super::TransactionMemo::RthWithPaymentRequestId {
                subaddress_index: Some(456),
                payment_request_id: 123,
            }
        );
    }

    #[test]
    fn transaction_memo_try_from_rth_payment_intent_id() {
        let mut rth = mc_mobilecoind_api::TransactionMemoRth {
            payment_id: Some(transaction_memo_rth::PaymentId::PaymentIntentId(123)),
            ..Default::default()
        };
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(transaction_memo::TransactionMemo::Rth(rth.clone())),
        };

        let result = super::TransactionMemo::try_from(&src).unwrap();
        assert_eq!(
            result,
            super::TransactionMemo::RthWithPaymentIntentId {
                subaddress_index: None,
                payment_intent_id: 123,
            }
        );

        rth.subaddress_index = Some(456);
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(transaction_memo::TransactionMemo::Rth(rth)),
        };

        let result = super::TransactionMemo::try_from(&src).unwrap();
        assert_eq!(
            result,
            super::TransactionMemo::RthWithPaymentIntentId {
                subaddress_index: Some(456),
                payment_intent_id: 123,
            }
        );
    }

    #[test]
    fn transaction_memo_try_from_empty() {
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(transaction_memo::TransactionMemo::Empty(Default::default())),
        };
        let result = super::TransactionMemo::try_from(&src).unwrap();
        assert_eq!(result, super::TransactionMemo::Empty);
    }

    #[test]
    fn transaction_memo_try_from_burn_redemption() {
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(transaction_memo::TransactionMemo::BurnRedemption(
                Default::default(),
            )),
        };
        let result = super::TransactionMemo::try_from(&src).unwrap_err();
        assert_eq!(result, ConversionError::ArrayCastError);

        let burn_redemption =
            mc_mobilecoind_api::TransactionMemoBurnRedemption { memo_data: vec![] };
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(transaction_memo::TransactionMemo::BurnRedemption(
                burn_redemption,
            )),
        };
        let result = super::TransactionMemo::try_from(&src).unwrap_err();
        assert_eq!(result, ConversionError::ArrayCastError);

        let burn_redemption = mc_mobilecoind_api::TransactionMemoBurnRedemption {
            memo_data: vec![1; BurnRedemptionMemo::MEMO_DATA_LEN - 1],
        };
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(transaction_memo::TransactionMemo::BurnRedemption(
                burn_redemption,
            )),
        };
        let result = super::TransactionMemo::try_from(&src).unwrap_err();
        assert_eq!(result, ConversionError::ArrayCastError);

        let burn_redemption = mc_mobilecoind_api::TransactionMemoBurnRedemption {
            memo_data: vec![1; BurnRedemptionMemo::MEMO_DATA_LEN],
        };
        let src = mobilecoind_api::TransactionMemo {
            transaction_memo: Some(transaction_memo::TransactionMemo::BurnRedemption(
                burn_redemption,
            )),
        };

        let result = super::TransactionMemo::try_from(&src).unwrap();
        assert_eq!(
            result,
            super::TransactionMemo::BurnRedemption([1; BurnRedemptionMemo::MEMO_DATA_LEN])
        );
    }
}
