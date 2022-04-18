// Copyright (c) 2018-2022 The MobileCoin Foundation

//! This module defines a helper object for tracking and accumulating fees
//! in the enclave, while remaining constant time with respect to token ids.
//! This is used both when looking up the fee for a transaction, and when
//! accumulating all the fees when forming a block.
//!
//! Note, in the future it may be more efficient to use data-structures / code
//! from the mc-oblivious repo, which is optimized for x86-64.

use alloc::vec::Vec;
use core::{
    iter::{FromIterator, IntoIterator},
    ops::Add,
};
use mc_transaction_core::TokenId;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

// A CtTokenMap is a structure mapping token ids to values.
// (For example, fees and minimum fees.)
//
// This structure supports get and set operations in constant time, by scanning
// across the list of pairs.
//
// Keys are set upon initialization, and cannot be added after initialization.
#[derive(Debug, Clone)]
pub struct CtTokenMap<T: ConditionallySelectable + Default> {
    storage: Vec<(TokenId, T)>,
}

impl<T: ConditionallySelectable + Default> CtTokenMap<T> {
    /// Get the value associated to a token id in constant time.
    ///
    /// If the token id is not found, returns None.
    ///
    /// Note that we do not return CtOption, it is not a goal to be
    /// constant-time with respect to whether the token is in the map, only
    /// that we are constant-time with respect to which token id it is that
    /// is in the map.
    pub fn get(&self, token_id: &TokenId) -> Option<T> {
        let mut success = Choice::from(0);
        let mut result = T::default();
        for (key, val) in self.storage.iter() {
            let found = key.ct_eq(token_id);
            result.conditional_assign(val, found);
            success.conditional_assign(&found, found);
        }
        if success.unwrap_u8() == 0 {
            None
        } else {
            Some(result)
        }
    }

    /// Set the value associated to a token id in constant time.
    ///
    /// This does not insert the token id if it was not set at initialization.
    /// If the token id is not present in the map, this function has no
    /// side-effect and returns false.
    // Note: this is not used right now, but we are leaving it in case we have
    // dynamic minimum fees at some point in the future.
    #[allow(dead_code)]
    pub fn set(&mut self, token_id: &TokenId, new_val: T) -> Choice {
        let mut success = Choice::from(0);
        for (key, val) in self.storage.iter_mut() {
            let found = key.ct_eq(token_id);
            val.conditional_assign(&new_val, found);
            success.conditional_assign(&found, found);
        }
        success
    }

    /// Add the value associated to a token id in constant time.
    ///
    /// This does not add the token id if it was not set at initialization.
    /// If the token id is not present in the map, this function has no
    /// side-effect and returns false.
    pub fn add(&mut self, token_id: &TokenId, addend: impl Copy + Add<T, Output = T>) -> Choice {
        let mut success = Choice::from(0);
        for (key, val) in self.storage.iter_mut() {
            let found = key.ct_eq(token_id);
            val.conditional_assign(&(addend + *val), found);
            success.conditional_assign(&found, found);
        }
        success
    }

    /// Get the number of key-value pairs in the map.
    pub fn len(&self) -> usize {
        self.storage.len()
    }

    /// Iterate over all entries in the map.
    pub fn iter(&self) -> impl Iterator<Item = &(TokenId, T)> + DoubleEndedIterator {
        self.storage.iter()
    }

    /// Get an iterator over the keys of this map.
    pub fn keys(&self) -> impl Iterator<Item = &TokenId> + DoubleEndedIterator {
        self.storage.iter().map(|(key, _val)| key)
    }
}

impl<T: ConstantTimeEq + ConditionallySelectable + Default> CtTokenMap<T> {
    /// Sort any zero values to the end in constant time.
    ///
    /// For accumulated fees, we want to create as few fee outputs as we can get
    /// away with, but without revealing any information about if some
    /// transactions had the same token id.
    ///
    /// To do this, we want to be able to collect all the "zero" values at the
    /// end of the buffer. This enables us to later discard some or all of them,
    /// without revealing over side-channels which token id's we discarded.
    ///
    /// This function systematically moves all the key-value pairs with zero
    /// value to the end, in constant time. The algorithm is like an
    /// insertion sort without early escapes, which should be fine for small
    /// buffers.
    pub fn sort_zeroes_to_end(&mut self) {
        if self.storage.len() < 2 {
            return;
        }

        let zero = T::default();
        for split_pos in (1..self.storage.len()).rev() {
            let (left, right) = self.storage.split_at_mut(split_pos);
            let next = &mut right[0];
            for candidate in left.iter_mut() {
                // Swap if the thing on the left is zero, and the right is nonzero
                // (In an insertion sort, this is just, swap if left < right)
                let should_swap = candidate.1.ct_eq(&zero) & !next.1.ct_eq(&zero);
                ConditionallySelectable::conditional_swap(
                    &mut next.0,
                    &mut candidate.0,
                    should_swap,
                );
                ConditionallySelectable::conditional_swap(
                    &mut next.1,
                    &mut candidate.1,
                    should_swap,
                );
            }
        }
    }
}

impl<T: ConditionallySelectable + Default> AsRef<[(TokenId, T)]> for CtTokenMap<T> {
    fn as_ref(&self) -> &[(TokenId, T)] {
        self.storage.as_ref()
    }
}

// Create a Ct token map from a sequence of key-value pairs.
//
// Note: If keys repeat in this sequence, it is not an error. The second
// instance of the key will be silently controlling. This is similar to how rust
// stdlib implements FromIter for maps.
impl<T: ConditionallySelectable + Default> FromIterator<(TokenId, T)> for CtTokenMap<T> {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (TokenId, T)>,
    {
        Self {
            storage: iter.into_iter().collect(),
        }
    }
}

// Create a Ct token map from a sequence of pairs of references to keys and
// values.
//
// Note: If keys repeat in this sequence, it is not an error. The second
// instance of the key will be silently controlling. This is similar to how rust
// stdlib implements FromIter for maps.
impl<'a, T: ConditionallySelectable + Default> FromIterator<(&'a TokenId, &'a T)>
    for CtTokenMap<T>
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (&'a TokenId, &'a T)>,
    {
        Self {
            storage: iter.into_iter().map(|(key, val)| (*key, *val)).collect(),
        }
    }
}

// Create a Ct token map from a sequence of keys. The values are all defaulted.
//
// Note: If keys repeat in this sequence, it is not an error, and the API will
// behave as expected. That is, the set of keys will be similar to if we did
// `BTreeSet::from(iter)` where `iter` contains repeats.
impl<T: ConditionallySelectable + Default> FromIterator<TokenId> for CtTokenMap<T> {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = TokenId>,
    {
        Self {
            storage: iter.into_iter().map(|key| (key, T::default())).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::{BTreeMap, BTreeSet};

    #[test]
    fn ct_token_map_get_and_set() {
        let mut map = CtTokenMap::from_iter([
            (TokenId::from(0), 0u64),
            (TokenId::from(1), 1u64),
            (TokenId::from(2), 2u64),
        ]);

        assert_eq!(map.get(&TokenId::from(0)), Some(0u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(2u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.set(&TokenId::from(0), 3u64);
        assert_eq!(result.unwrap_u8(), 1);

        assert_eq!(map.get(&TokenId::from(0)), Some(3u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(2u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.set(&TokenId::from(0), 4u64);
        assert_eq!(result.unwrap_u8(), 1);

        assert_eq!(map.get(&TokenId::from(0)), Some(4u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(2u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.set(&TokenId::from(2), 9u64);
        assert_eq!(result.unwrap_u8(), 1);

        assert_eq!(map.get(&TokenId::from(0)), Some(4u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(9u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.set(&TokenId::from(3), 17u64);
        assert_eq!(result.unwrap_u8(), 0);

        assert_eq!(map.get(&TokenId::from(0)), Some(4u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(9u64));
        assert_eq!(map.get(&TokenId::from(3)), None);
    }

    #[test]
    fn ct_token_map_get_and_set_repeat_elements_one() {
        let mut map = CtTokenMap::from_iter([
            (TokenId::from(0), 0u64),
            (TokenId::from(1), 1u64),
            (TokenId::from(2), 2u64),
            (TokenId::from(0), 0u64),
        ]);

        assert_eq!(map.get(&TokenId::from(0)), Some(0u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(2u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.set(&TokenId::from(0), 3u64);
        assert_eq!(result.unwrap_u8(), 1);

        assert_eq!(map.get(&TokenId::from(0)), Some(3u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(2u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.set(&TokenId::from(0), 4u64);
        assert_eq!(result.unwrap_u8(), 1);

        assert_eq!(map.get(&TokenId::from(0)), Some(4u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(2u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.set(&TokenId::from(2), 9u64);
        assert_eq!(result.unwrap_u8(), 1);

        assert_eq!(map.get(&TokenId::from(0)), Some(4u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(9u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.set(&TokenId::from(3), 17u64);
        assert_eq!(result.unwrap_u8(), 0);

        assert_eq!(map.get(&TokenId::from(0)), Some(4u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(9u64));
        assert_eq!(map.get(&TokenId::from(3)), None);
    }

    #[test]
    fn ct_token_map_get_and_set_repeat_elements_two() {
        let mut map = CtTokenMap::from_iter([
            (TokenId::from(0), 7u64),
            (TokenId::from(1), 1u64),
            (TokenId::from(2), 2u64),
            (TokenId::from(0), 0u64),
        ]);

        assert_eq!(map.get(&TokenId::from(0)), Some(0u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(2u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.set(&TokenId::from(0), 3u64);
        assert_eq!(result.unwrap_u8(), 1);

        assert_eq!(map.get(&TokenId::from(0)), Some(3u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(2u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.set(&TokenId::from(0), 4u64);
        assert_eq!(result.unwrap_u8(), 1);

        assert_eq!(map.get(&TokenId::from(0)), Some(4u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(2u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.set(&TokenId::from(2), 9u64);
        assert_eq!(result.unwrap_u8(), 1);

        assert_eq!(map.get(&TokenId::from(0)), Some(4u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(9u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.set(&TokenId::from(3), 17u64);
        assert_eq!(result.unwrap_u8(), 0);

        assert_eq!(map.get(&TokenId::from(0)), Some(4u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(9u64));
        assert_eq!(map.get(&TokenId::from(3)), None);
    }

    #[test]
    fn ct_token_map_add() {
        let mut map = CtTokenMap::from_iter([
            (TokenId::from(0), 0u64),
            (TokenId::from(1), 1u64),
            (TokenId::from(2), 2u64),
        ]);

        assert_eq!(map.get(&TokenId::from(0)), Some(0u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(2u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.add(&TokenId::from(0), 3u64);
        assert_eq!(result.unwrap_u8(), 1);

        assert_eq!(map.get(&TokenId::from(0)), Some(3u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(2u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.add(&TokenId::from(0), 4u64);
        assert_eq!(result.unwrap_u8(), 1);

        assert_eq!(map.get(&TokenId::from(0)), Some(7u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(2u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.add(&TokenId::from(2), 9u64);
        assert_eq!(result.unwrap_u8(), 1);

        assert_eq!(map.get(&TokenId::from(0)), Some(7u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(11u64));
        assert_eq!(map.get(&TokenId::from(3)), None);

        let result = map.add(&TokenId::from(3), 17u64);
        assert_eq!(result.unwrap_u8(), 0);

        assert_eq!(map.get(&TokenId::from(0)), Some(7u64));
        assert_eq!(map.get(&TokenId::from(1)), Some(1u64));
        assert_eq!(map.get(&TokenId::from(2)), Some(11u64));
        assert_eq!(map.get(&TokenId::from(3)), None);
    }

    fn take_ending_zeroes(map: &CtTokenMap<u64>) -> BTreeSet<TokenId> {
        map.iter()
            .rev()
            .take_while(|pair| pair.1 == 0)
            .map(|pair| pair.0)
            .collect()
    }

    fn token_id_set(ids: &[u64]) -> BTreeSet<TokenId> {
        ids.iter().map(|id| TokenId::from(*id)).collect()
    }

    fn to_btree_map(map: &CtTokenMap<u64>) -> BTreeMap<TokenId, u64> {
        map.as_ref().iter().cloned().collect()
    }

    #[test]
    fn ct_token_map_sort_zeroes_to_end() {
        let orig_map = CtTokenMap::from_iter([
            (TokenId::from(0), 0u64),
            (TokenId::from(1), 1u64),
            (TokenId::from(2), 2u64),
        ]);
        let mut map = orig_map.clone();
        map.sort_zeroes_to_end();

        assert_eq!(to_btree_map(&orig_map), to_btree_map(&map));
        assert_eq!(take_ending_zeroes(&map), token_id_set(&[0]));

        let orig_map = CtTokenMap::from_iter([
            (TokenId::from(2), 2u64),
            (TokenId::from(1), 1u64),
            (TokenId::from(0), 0u64),
        ]);
        let mut map = orig_map.clone();
        map.sort_zeroes_to_end();
        assert_eq!(to_btree_map(&orig_map), to_btree_map(&map));
        assert_eq!(take_ending_zeroes(&map), token_id_set(&[0]));

        let orig_map = CtTokenMap::from_iter([
            (TokenId::from(1), 1u64),
            (TokenId::from(0), 0u64),
            (TokenId::from(2), 2u64),
        ]);
        let mut map = orig_map.clone();
        map.sort_zeroes_to_end();
        assert_eq!(to_btree_map(&orig_map), to_btree_map(&map));
        assert_eq!(take_ending_zeroes(&map), token_id_set(&[0]));

        let orig_map = CtTokenMap::from_iter([
            (TokenId::from(0), 0u64),
            (TokenId::from(1), 0u64),
            (TokenId::from(2), 2u64),
        ]);
        let mut map = orig_map.clone();
        map.sort_zeroes_to_end();
        assert_eq!(to_btree_map(&orig_map), to_btree_map(&map));
        assert_eq!(take_ending_zeroes(&map), token_id_set(&[0, 1]));

        let orig_map = CtTokenMap::from_iter([
            (TokenId::from(0), 0u64),
            (TokenId::from(2), 2u64),
            (TokenId::from(1), 0u64),
        ]);
        let mut map = orig_map.clone();
        map.sort_zeroes_to_end();
        assert_eq!(to_btree_map(&orig_map), to_btree_map(&map));
        assert_eq!(take_ending_zeroes(&map), token_id_set(&[0, 1]));

        let orig_map = CtTokenMap::from_iter([
            (TokenId::from(0), 3u64),
            (TokenId::from(1), 0u64),
            (TokenId::from(2), 2u64),
        ]);
        let mut map = orig_map.clone();
        map.sort_zeroes_to_end();
        assert_eq!(to_btree_map(&orig_map), to_btree_map(&map));
        assert_eq!(take_ending_zeroes(&map), token_id_set(&[1]));

        let orig_map = CtTokenMap::from_iter([
            (TokenId::from(1), 0u64),
            (TokenId::from(0), 3u64),
            (TokenId::from(2), 2u64),
        ]);
        let mut map = orig_map.clone();
        map.sort_zeroes_to_end();
        assert_eq!(to_btree_map(&orig_map), to_btree_map(&map));
        assert_eq!(take_ending_zeroes(&map), token_id_set(&[1]));

        let orig_map = CtTokenMap::from_iter([
            (TokenId::from(1), 0u64),
            (TokenId::from(2), 0u64),
            (TokenId::from(0), 3u64),
        ]);
        let mut map = orig_map.clone();
        map.sort_zeroes_to_end();
        assert_eq!(to_btree_map(&orig_map), to_btree_map(&map));
        assert_eq!(take_ending_zeroes(&map), token_id_set(&[1, 2]));

        let orig_map = CtTokenMap::from_iter([
            (TokenId::from(0), 3u64),
            (TokenId::from(1), 9u64),
            (TokenId::from(2), 7u64),
        ]);
        let mut map = orig_map.clone();
        map.sort_zeroes_to_end();
        assert_eq!(to_btree_map(&orig_map), to_btree_map(&map));
        assert_eq!(take_ending_zeroes(&map), token_id_set(&[]));
    }
}
