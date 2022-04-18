// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A helper object for maintaining a map of token id -> master minters
//! signatures.

use alloc::collections::BTreeMap;
use core::{convert::TryFrom, iter::FromIterator};
use displaydoc::Display;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::Ed25519Public;
use mc_crypto_multisig::SignerSet;
use mc_transaction_core::{tokens::Mob, Token, TokenId};
use serde::{Deserialize, Serialize};

/// A map of master minters by token id.
#[derive(Clone, Debug, Default, Deserialize, Digestible, Eq, Hash, PartialEq, Serialize)]
pub struct MasterMintersMap {
    /// The actual map of token_id to master minters.
    /// Since we hash this map, it is important to use a BTreeMap as it
    /// guarantees iterating over the map is in sorted and predictable
    /// order.
    map: BTreeMap<TokenId, SignerSet<Ed25519Public>>,
}

impl TryFrom<BTreeMap<TokenId, SignerSet<Ed25519Public>>> for MasterMintersMap {
    type Error = Error;

    fn try_from(map: BTreeMap<TokenId, SignerSet<Ed25519Public>>) -> Result<Self, Self::Error> {
        Self::is_valid_map(&map)?;

        Ok(Self { map })
    }
}

impl AsRef<BTreeMap<TokenId, SignerSet<Ed25519Public>>> for MasterMintersMap {
    fn as_ref(&self) -> &BTreeMap<TokenId, SignerSet<Ed25519Public>> {
        &self.map
    }
}

impl MasterMintersMap {
    /// Create a map from an unsorted iterator.
    pub fn try_from_iter(
        iter: impl IntoIterator<Item = (TokenId, SignerSet<Ed25519Public>)>,
    ) -> Result<Self, Error> {
        let map = BTreeMap::from_iter(iter);
        Self::try_from(map)
    }

    /// Get the master mintersfor a given token id, or None if token has no
    /// master minters.
    pub fn get_master_minters_for_token(
        &self,
        token_id: &TokenId,
    ) -> Option<SignerSet<Ed25519Public>> {
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
            // Must have at least as many signers as the threshold.
            if signer_set.threshold() as usize > signer_set.signers().len() {
                return Err(Error::InsufficientSigners(*token_id));
            }

            // Must have at least one signer.
            if signer_set.signers().is_empty() {
                return Err(Error::InsufficientSigners(*token_id));
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

/// MasterMinters Map error type.
#[derive(Clone, Debug, Deserialize, Display, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    /// Mob token is not allowed to be a master minter.
    MobTokenNotAllowed,

    /// Token `{0}` has insufficient signers
    InsufficientSigners(TokenId),
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;

    /// Valid maps should be accepted
    #[test]
    fn valid_maps_accepted() {
        let map1 = MasterMintersMap::try_from_iter([
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

        assert!(map1
            .get_master_minters_for_token(&TokenId::from(1))
            .is_some());
        assert!(map1
            .get_master_minters_for_token(&TokenId::from(2))
            .is_some());
        assert!(map1
            .get_master_minters_for_token(&TokenId::from(3))
            .is_none());

        let map2 = MasterMintersMap::try_from_iter([
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

        assert!(map2
            .get_master_minters_for_token(&TokenId::from(1))
            .is_some());
        assert!(map2
            .get_master_minters_for_token(&TokenId::from(2))
            .is_some());
        assert!(map2
            .get_master_minters_for_token(&TokenId::from(3))
            .is_none());

        let map3 = MasterMintersMap::try_from_iter([]).unwrap();
        assert!(map3
            .get_master_minters_for_token(&TokenId::from(1))
            .is_none());
        assert!(map3
            .get_master_minters_for_token(&TokenId::from(2))
            .is_none());
        assert!(map3
            .get_master_minters_for_token(&TokenId::from(3))
            .is_none());
    }

    /// Invalid are rejected.
    #[test]
    fn invalid_are_rejected() {
        let test_token_id = TokenId::from(2);

        // MOB is not allowed
        assert_eq!(
            MasterMintersMap::is_valid_map(&BTreeMap::from_iter(vec![(
                Mob::ID,
                SignerSet::new(vec![Ed25519Public::default()], 1)
            )])),
            Err(Error::MobTokenNotAllowed),
        );

        // Empty signers not allowed.
        assert_eq!(
            MasterMintersMap::is_valid_map(&BTreeMap::from_iter(vec![(
                test_token_id,
                SignerSet::new(vec![], 0)
            )])),
            Err(Error::InsufficientSigners(test_token_id)),
        );
        assert_eq!(
            MasterMintersMap::is_valid_map(&BTreeMap::from_iter(vec![(
                test_token_id,
                SignerSet::new(vec![], 1)
            )])),
            Err(Error::InsufficientSigners(test_token_id)),
        );

        // Threshold > signers not allowed
        assert_eq!(
            MasterMintersMap::is_valid_map(&BTreeMap::from_iter(vec![(
                test_token_id,
                SignerSet::new(vec![Ed25519Public::default()], 2)
            )])),
            Err(Error::InsufficientSigners(test_token_id)),
        );
    }
}
