// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A helper object for maintaining a map of token id -> governors
//! signatures.

use alloc::collections::BTreeMap;
use displaydoc::Display;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::Ed25519Public;
use mc_crypto_multisig::SignerSet;
use mc_transaction_core::{tokens::Mob, Token, TokenId};
use serde::{Deserialize, Serialize};

/// A map of governors by token id.
#[derive(Clone, Debug, Default, Deserialize, Digestible, Eq, Hash, PartialEq, Serialize)]
pub struct GovernorsMap {
    /// The actual map of token_id to governors.
    /// Since we hash this map, it is important to use a BTreeMap as it
    /// guarantees iterating over the map is in sorted and predictable
    /// order.
    map: BTreeMap<TokenId, SignerSet<Ed25519Public>>,
}

impl TryFrom<BTreeMap<TokenId, SignerSet<Ed25519Public>>> for GovernorsMap {
    type Error = Error;

    fn try_from(map: BTreeMap<TokenId, SignerSet<Ed25519Public>>) -> Result<Self, Self::Error> {
        Self::is_valid_map(&map)?;

        Ok(Self { map })
    }
}

impl AsRef<BTreeMap<TokenId, SignerSet<Ed25519Public>>> for GovernorsMap {
    fn as_ref(&self) -> &BTreeMap<TokenId, SignerSet<Ed25519Public>> {
        &self.map
    }
}

impl GovernorsMap {
    /// Create a map from an unsorted iterator.
    pub fn try_from_iter(
        iter: impl IntoIterator<Item = (TokenId, SignerSet<Ed25519Public>)>,
    ) -> Result<Self, Error> {
        let map = BTreeMap::from_iter(iter);
        Self::try_from(map)
    }

    /// Get the governors for a given token id, or None if the token has no
    /// governors.
    pub fn get_governors_for_token(&self, token_id: &TokenId) -> Option<SignerSet<Ed25519Public>> {
        self.map.get(token_id).cloned()
    }

    /// Update the map with a new one if provided, or reset it to the
    /// default.
    pub fn update_or_default(
        &mut self,
        map: Option<BTreeMap<TokenId, SignerSet<Ed25519Public>>>,
    ) -> Result<(), Error> {
        if let Some(map) = map {
            Self::is_valid_map(&map)?;

            self.map = map;
        } else {
            self.map = Default::default();
        }

        Ok(())
    }

    /// Check if a given map is valid.
    pub fn is_valid_map(map: &BTreeMap<TokenId, SignerSet<Ed25519Public>>) -> Result<(), Error> {
        // Can never mint MOB.
        if map.contains_key(&Mob::ID) {
            return Err(Error::MobTokenNotAllowed);
        }

        // Validate individual entries.
        for (token_id, signer_set) in map.iter() {
            if !signer_set.is_valid() {
                return Err(Error::InvalidSignerSet(*token_id));
            }
        }

        // All good.
        Ok(())
    }

    /// Iterate over all entries in the map.
    pub fn iter(&self) -> impl Iterator<Item = (&TokenId, &SignerSet<Ed25519Public>)> {
        self.map.iter()
    }

    /// Check if the map contains any elements.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Governors Map error type.
#[derive(Clone, Debug, Deserialize, Display, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    /// Mob token is not allowed to have governors.
    MobTokenNotAllowed,

    /// Token `{0}` has an invalid signer set
    InvalidSignerSet(TokenId),
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;

    /// Valid maps should be accepted
    #[test]
    fn valid_maps_accepted() {
        let map1 = GovernorsMap::try_from_iter([
            (
                TokenId::from(1),
                SignerSet::new(vec![Ed25519Public::default()], 1),
            ),
            (
                TokenId::from(2),
                SignerSet::new(vec![Ed25519Public::default()], 1),
            ),
        ])
        .unwrap();

        assert!(map1.get_governors_for_token(&TokenId::from(1)).is_some());
        assert!(map1.get_governors_for_token(&TokenId::from(2)).is_some());
        assert!(map1.get_governors_for_token(&TokenId::from(3)).is_none());

        let map2 = GovernorsMap::try_from_iter([
            (
                TokenId::from(1),
                SignerSet::new(vec![Ed25519Public::default()], 1),
            ),
            (
                TokenId::from(2),
                SignerSet::new(vec![Ed25519Public::default(), Ed25519Public::default()], 2),
            ),
        ])
        .unwrap();

        assert!(map2.get_governors_for_token(&TokenId::from(1)).is_some());
        assert!(map2.get_governors_for_token(&TokenId::from(2)).is_some());
        assert!(map2.get_governors_for_token(&TokenId::from(3)).is_none());

        let map3 = GovernorsMap::try_from_iter([]).unwrap();
        assert!(map3.get_governors_for_token(&TokenId::from(1)).is_none());
        assert!(map3.get_governors_for_token(&TokenId::from(2)).is_none());
        assert!(map3.get_governors_for_token(&TokenId::from(3)).is_none());
    }

    /// Invalid are rejected.
    #[test]
    fn invalid_are_rejected() {
        let test_token_id = TokenId::from(2);

        // MOB is not allowed
        assert_eq!(
            GovernorsMap::is_valid_map(&BTreeMap::from_iter(vec![(
                Mob::ID,
                SignerSet::new(vec![Ed25519Public::default()], 1)
            )])),
            Err(Error::MobTokenNotAllowed),
        );

        // Empty signers not allowed.
        assert_eq!(
            GovernorsMap::is_valid_map(&BTreeMap::from_iter(vec![(
                test_token_id,
                SignerSet::new(vec![], 0)
            )])),
            Err(Error::InvalidSignerSet(test_token_id)),
        );
        assert_eq!(
            GovernorsMap::is_valid_map(&BTreeMap::from_iter(vec![(
                test_token_id,
                SignerSet::new(vec![], 1)
            )])),
            Err(Error::InvalidSignerSet(test_token_id)),
        );

        // Threshold > signers not allowed
        assert_eq!(
            GovernorsMap::is_valid_map(&BTreeMap::from_iter(vec![(
                test_token_id,
                SignerSet::new(vec![Ed25519Public::default()], 2)
            )])),
            Err(Error::InvalidSignerSet(test_token_id)),
        );
    }
}
