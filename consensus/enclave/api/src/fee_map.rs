// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A helper object for maintaining a map of token id -> minimum fee.

use alloc::collections::BTreeMap;
use core::{convert::TryFrom, iter::FromIterator};
use displaydoc::Display;
use mc_crypto_digestible::Digestible;
use mc_transaction_core::{tokens::Mob, Token, TokenId};
use serde::{Deserialize, Serialize};

/// A thread-safe object that contains a map of fee value by token id.
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
        // All fees must be greater than 0.
        if let Some((token_id, fee)) = minimum_fees.iter().find(|(_token_id, fee)| **fee == 0) {
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
        let fee_map1 = FeeMap::try_from_iter([(Mob::ID, 100), (TokenId::from(2), 2000)]).unwrap();
        assert!(fee_map1.get_fee_for_token(&Mob::ID).is_some());

        let fee_map2 = FeeMap::try_from_iter([(Mob::ID, 100), (TokenId::from(2), 300)]).unwrap();
        assert!(fee_map2.get_fee_for_token(&Mob::ID).is_some());

        let fee_map3 = FeeMap::try_from_iter([(Mob::ID, 100), (TokenId::from(30), 300)]).unwrap();
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
            FeeMap::is_valid_map(&BTreeMap::from_iter(vec![(test_token_id, 100)])),
            Err(Error::MissingFee(Mob::ID)),
        );

        // All fees must be >0
        assert_eq!(
            FeeMap::is_valid_map(&BTreeMap::from_iter(vec![(Mob::ID, 0)])),
            Err(Error::InvalidFee(Mob::ID, 0)),
        );

        assert_eq!(
            FeeMap::is_valid_map(&BTreeMap::from_iter(vec![
                (Mob::ID, 10),
                (test_token_id, 0)
            ])),
            Err(Error::InvalidFee(test_token_id, 0)),
        );
    }
}
