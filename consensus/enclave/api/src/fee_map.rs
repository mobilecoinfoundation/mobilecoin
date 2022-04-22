// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A helper object for maintaining a map of token id -> minimum fee.

use alloc::collections::BTreeMap;
use core::{convert::TryFrom, iter::FromIterator};
use displaydoc::Display;
use mc_crypto_digestible::Digestible;
use mc_transaction_core::{tokens::Mob, Token, TokenId};
use serde::{Deserialize, Serialize};

/// The log base 2 of the smallest allowed minimum fee, in the smallest
/// representable units.
/// This minimum exists because it helps the computation of priority from fees
/// to work in a nice way.
///
/// Priority is computed by "normalizing" the fee for each token, using the
/// minimum fee. However, before dividing fee by minimum fee, we divide minimum
/// fee by (1 << 7) = 128.
///
/// This allows that if you increase the fee by e.g. 1%, then it always leads to
/// an integer difference in the priority and leads to your
/// transaction actually being ranked higher when the network sorts the tx's.
///
/// If we don't do this, then you can only increase the fee paid in increments
/// of the minimum fee to see an actual increase in priority. So effectively,
/// once the network is under load, the fees immediately double, then triple.
/// This seems undesirable.
///
/// (The choice of 128 is arbitrary, it's the first power of two >= 100.)
///
/// Because we divide minimum fee by by 128, and the result must be nonzero, we
/// must have that the minimum fee itself is at least as large as what we are
/// dividing by. This is fine because 128 in the smallest representable units is
/// a negligible amount of any currency.
///
/// The smallest allowed minimum fee is required to be a power of two, because
/// dividing by a power of two is fast and constant time.
pub const SMALLEST_MINIMUM_FEE_LOG2: u64 = 7;

/// A map of fee value by token id.
#[derive(Clone, Debug, Deserialize, Digestible, Eq, Hash, PartialEq, Serialize)]
pub struct FeeMap {
    /// The actual map of token_id to fee.
    /// Since we hash this map, it is important to use a BTreeMap as it
    /// guarantees iterating over the map is in sorted and predictable
    /// order.
    map: BTreeMap<TokenId, u64>,
}

impl Default for FeeMap {
    fn default() -> Self {
        let map = Self::default_map();

        Self { map }
    }
}

impl TryFrom<BTreeMap<TokenId, u64>> for FeeMap {
    type Error = Error;

    fn try_from(map: BTreeMap<TokenId, u64>) -> Result<Self, Self::Error> {
        Self::is_valid_map(&map)?;

        Ok(Self { map })
    }
}

impl AsRef<BTreeMap<TokenId, u64>> for FeeMap {
    fn as_ref(&self) -> &BTreeMap<TokenId, u64> {
        &self.map
    }
}

impl FeeMap {
    /// Create a fee map from an unsorted iterator.
    pub fn try_from_iter(iter: impl IntoIterator<Item = (TokenId, u64)>) -> Result<Self, Error> {
        let map = BTreeMap::from_iter(iter);
        Self::try_from(map)
    }

    /// Get the fee for a given token id, or None if no fee is set for that
    /// token.
    pub fn get_fee_for_token(&self, token_id: &TokenId) -> Option<u64> {
        self.map.get(token_id).cloned()
    }

    /// Update the fee map with a new one if provided, or reset it to the
    /// default.
    pub fn update_or_default(
        &mut self,
        minimum_fees: Option<BTreeMap<TokenId, u64>>,
    ) -> Result<(), Error> {
        if let Some(minimum_fees) = minimum_fees {
            Self::is_valid_map(&minimum_fees)?;

            self.map = minimum_fees;
        } else {
            self.map = Self::default_map();
        }

        Ok(())
    }

    /// Check if a given fee map is valid.
    pub fn is_valid_map(minimum_fees: &BTreeMap<TokenId, u64>) -> Result<(), Error> {
        // All minimum fees must be greater than 128 in the smallest representable unit.
        // This is because we divide the minimum fee by 128 when computing priority
        // numbers, to allow that increments of 1% of the minimum fee affect the
        // priority of a payment.
        if let Some((token_id, fee)) = minimum_fees
            .iter()
            .find(|(_token_id, fee)| (**fee >> SMALLEST_MINIMUM_FEE_LOG2) == 0)
        {
            return Err(Error::InvalidFee(*token_id, *fee));
        }

        // Must have a minimum fee for MOB.
        if !minimum_fees.contains_key(&Mob::ID) {
            return Err(Error::MissingFee(Mob::ID));
        }

        // All good.
        Ok(())
    }

    /// Iterate over all entries in the fee map.
    pub fn iter(&self) -> impl Iterator<Item = (&TokenId, &u64)> {
        self.map.iter()
    }

    /// Helper method for constructing the default fee map.
    pub fn default_map() -> BTreeMap<TokenId, u64> {
        let mut map = BTreeMap::new();
        map.insert(Mob::ID, Mob::MINIMUM_FEE);
        map
    }
}

/// Fee Map error type.
#[derive(Clone, Debug, Deserialize, Display, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    /// Token `{0}` has invalid fee `{1}`
    InvalidFee(TokenId, u64),

    /// Token `{0}` is missing from the fee map
    MissingFee(TokenId),
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;

    /// Valid fee maps ids should be accepted
    #[test]
    fn valid_fee_maps_accepted() {
        let fee_map1 = FeeMap::try_from_iter([(Mob::ID, 1000), (TokenId::from(2), 20000)]).unwrap();
        assert!(fee_map1.get_fee_for_token(&Mob::ID).is_some());

        let fee_map2 = FeeMap::try_from_iter([(Mob::ID, 1000), (TokenId::from(2), 3000)]).unwrap();
        assert!(fee_map2.get_fee_for_token(&Mob::ID).is_some());

        let fee_map3 = FeeMap::try_from_iter([(Mob::ID, 1000), (TokenId::from(30), 3000)]).unwrap();
        assert!(fee_map3.get_fee_for_token(&Mob::ID).is_some());
    }

    /// Invalid fee maps are rejected.
    #[test]
    fn invalid_fee_maps_are_rejected() {
        let test_token_id = TokenId::from(2);

        // Missing MOB is not allowed
        assert_eq!(
            FeeMap::is_valid_map(&BTreeMap::default()),
            Err(Error::MissingFee(Mob::ID)),
        );

        assert_eq!(
            FeeMap::is_valid_map(&BTreeMap::from_iter(vec![(test_token_id, 1000)])),
            Err(Error::MissingFee(Mob::ID)),
        );

        // All fees must be >0
        assert_eq!(
            FeeMap::is_valid_map(&BTreeMap::from_iter(vec![(Mob::ID, 0)])),
            Err(Error::InvalidFee(Mob::ID, 0)),
        );

        assert_eq!(
            FeeMap::is_valid_map(&BTreeMap::from_iter(vec![(Mob::ID, 10)])),
            Err(Error::InvalidFee(Mob::ID, 10)),
        );

        assert_eq!(
            FeeMap::is_valid_map(&BTreeMap::from_iter(vec![
                (Mob::ID, 1000),
                (test_token_id, 0)
            ])),
            Err(Error::InvalidFee(test_token_id, 0)),
        );
    }
}
