// Copyright (c) 2018-2024 The MobileCoin Foundation

use mc_api::ConversionError;
use mc_mobilecoind_api::{
    mobilecoind_api, TransactionMemo_RTH_oneof_payment_id, TransactionMemo_oneof_transaction_memo,
};
use mc_transaction_extra::BurnRedemptionMemo;

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
