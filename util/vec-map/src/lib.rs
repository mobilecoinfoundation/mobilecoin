// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Provides a map (key-value store) interface backed by `heapless::Vec`

#![deny(missing_docs)]

use displaydoc::Display;
use heapless::Vec;

/// An error which can occur when using VecMap
#[derive(Clone, Debug, Display)]
pub enum Error {
    /// VecMap capacity exceeded
    CapacityExceeded,
}

/// This is a mini version of VecMap that is no_std compatible and uses
/// heapless::Vec instead alloc::Vec.
///
/// It may be better to patch upstream for no_std compatibility and use that,
/// but that crate has other issues -- it relies on an
/// experimental "contracts" crate that causes a dependency on rand crate.
/// Porting to Heapless would be a breaking chnage to the API.
///
/// TBD what the best path is: https://github.com/p-avital/vec-map-rs/blob/master/src/lib.rs
#[derive(Clone, Debug)]
pub struct VecMap<K: Clone + Eq + PartialEq, V, const N: usize> {
    keys: Vec<K, N>,
    values: Vec<V, N>,
}

impl<K: Clone + Eq + PartialEq, V, const N: usize> Default for VecMap<K, V, N> {
    fn default() -> Self {
        Self {
            keys: Default::default(),
            values: Default::default(),
        }
    }
}

impl<K: Clone + Eq + PartialEq, V, const N: usize> VecMap<K, V, N> {
    /// Check if the map is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the number of items in the map
    #[inline]
    pub fn len(&self) -> usize {
        debug_assert!(self.keys.len() == self.values.len());
        self.keys.len()
    }

    /// Get the value associated to a key, if present
    pub fn get<'a>(&'a self, key: &K) -> Option<&'a V> {
        self.keys
            .iter()
            .position(|k| k == key)
            .map(|idx| &self.values[idx])
    }

    /// Get a mutable reference to the value associated to a key, if present
    pub fn get_mut<'a>(&'a mut self, key: &K) -> Option<&'a mut V> {
        self.keys
            .iter()
            .position(|k| k == key)
            .map(|idx| &mut self.values[idx])
    }

    /// Get a mutable reference to the value associated to a key, if present,
    /// or else insert such a value produced by given callback,
    /// and then return a mutable reference
    ///
    /// Returns an error if the heapless::Vec capacity was exceeded
    pub fn get_mut_or_insert_with<'a>(
        &'a mut self,
        key: &K,
        val_fn: impl FnOnce() -> V,
    ) -> Result<&'a mut V, Error> {
        if let Some(idx) = self.keys.iter().position(|k| k == key) {
            Ok(&mut self.values[idx])
        } else {
            let idx = self.keys.len();
            debug_assert_eq!(idx, self.values.len());
            self.keys
                .push(key.clone())
                .map_err(|_| Error::CapacityExceeded)?;
            self.values
                .push(val_fn())
                .map_err(|_| Error::CapacityExceeded)?;
            Ok(&mut self.values[idx])
        }
    }

    /// Get an iterator over the pairs in the VecMap
    pub fn iter(&self) -> IterVecMap<K, V, N> {
        IterVecMap::new(self)
    }
}

// Sorting is possible when keys are ordered, and keys and values are cloneable
impl<K: Clone + Ord + PartialOrd + Eq + PartialEq, V: Clone, const N: usize> VecMap<K, V, N> {
    /// Sort the key-value pairs of the VecMap
    pub fn sort(&mut self) {
        // First compute the order that would sort the set of keys
        let mut indices: Vec<usize, N> = (0..self.keys.len()).collect();
        indices.sort_by_key(|&i| &self.keys[i]);
        // Make new key and val sets
        let mut new_keys = Vec::<K, N>::default();
        let mut new_vals = Vec::<V, N>::default();
        // Push items into the new sets in appropriate order
        for idx in indices {
            // Safety: This is okay because indices
            // has length at most n, so we are pushing at most n
            // things into new_keys and new_vals.
            unsafe { new_keys.push_unchecked(self.keys[idx].clone()) };
            unsafe { new_vals.push_unchecked(self.values[idx].clone()) };
        }
        // Overwrite old sets
        self.keys = new_keys;
        self.values = new_vals;
    }
}

/// An iterator over a VecMap
pub struct IterVecMap<'a, K: Clone + Eq + PartialEq, V, const N: usize> {
    src: &'a VecMap<K, V, N>,
    idx: usize,
}

impl<'a, K: Clone + Eq + PartialEq, V, const N: usize> IterVecMap<'a, K, V, N> {
    fn new(src: &'a VecMap<K, V, N>) -> Self {
        Self { src, idx: 0 }
    }
}

impl<'a, K: Clone + Eq + PartialEq, V, const N: usize> Iterator for IterVecMap<'a, K, V, N> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.src.keys.get(self.idx).and_then(|key_ref| {
            self.src
                .values
                .get(self.idx)
                .map(|value_ref| (key_ref, value_ref))
        });
        self.idx += 1;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    #[test]
    fn test_get_mut_or_insert_with() {
        let mut vec_map = VecMap::<u32, u64, 4>::default();
        assert_eq!(*vec_map.get_mut_or_insert_with(&3, || 5).unwrap(), 5);
        assert_eq!(*vec_map.get_mut_or_insert_with(&4, || 6).unwrap(), 6);
        assert_eq!(*vec_map.get_mut_or_insert_with(&7, || 6).unwrap(), 6);
        assert_eq!(*vec_map.get_mut_or_insert_with(&8, || 10).unwrap(), 10);
        assert!(vec_map.get_mut_or_insert_with(&9, || 11).is_err());
        assert_eq!(vec_map.len(), 4);
        assert_eq!(*vec_map.get_mut_or_insert_with(&7, || 10).unwrap(), 6);
        assert_eq!(vec_map.len(), 4);
    }

    #[test]
    fn test_get() {
        let mut vec_map = VecMap::<u32, u64, 4>::default();
        assert_eq!(*vec_map.get_mut_or_insert_with(&3, || 5).unwrap(), 5);
        assert_eq!(*vec_map.get_mut_or_insert_with(&4, || 6).unwrap(), 6);
        assert_eq!(*vec_map.get_mut_or_insert_with(&7, || 6).unwrap(), 6);
        assert_eq!(*vec_map.get_mut_or_insert_with(&8, || 10).unwrap(), 10);

        assert_eq!(vec_map.get(&3), Some(&5));
        assert_eq!(vec_map.get(&4), Some(&6));
        assert_eq!(vec_map.get(&5), None);
        assert_eq!(vec_map.get(&6), None);
        assert_eq!(vec_map.get(&7), Some(&6));
        assert_eq!(vec_map.get(&8), Some(&10));
    }

    #[test]
    fn test_get_mut() {
        let mut vec_map = VecMap::<u32, u64, 4>::default();
        assert_eq!(*vec_map.get_mut_or_insert_with(&3, || 5).unwrap(), 5);
        assert_eq!(*vec_map.get_mut_or_insert_with(&4, || 6).unwrap(), 6);
        assert_eq!(*vec_map.get_mut_or_insert_with(&7, || 6).unwrap(), 6);
        assert_eq!(*vec_map.get_mut_or_insert_with(&8, || 10).unwrap(), 10);

        assert_eq!(vec_map.get_mut(&3), Some(5).as_mut());
        assert_eq!(vec_map.get_mut(&4), Some(6).as_mut());
        assert_eq!(vec_map.get_mut(&5), None);
        assert_eq!(vec_map.get_mut(&6), None);
        assert_eq!(vec_map.get_mut(&7), Some(6).as_mut());
        assert_eq!(vec_map.get_mut(&8), Some(10).as_mut());
    }

    #[test]
    fn test_iter() {
        let mut vec_map = VecMap::<u32, u64, 4>::default();
        assert_eq!(*vec_map.get_mut_or_insert_with(&3, || 5).unwrap(), 5);
        assert_eq!(*vec_map.get_mut_or_insert_with(&4, || 6).unwrap(), 6);
        assert_eq!(*vec_map.get_mut_or_insert_with(&7, || 6).unwrap(), 6);
        assert_eq!(*vec_map.get_mut_or_insert_with(&8, || 10).unwrap(), 10);

        let seq: alloc::vec::Vec<_> = vec_map.iter().collect();
        assert_eq!(seq.len(), 4);
        assert_eq!(seq[0], (&3, &5));
        assert_eq!(seq[1], (&4, &6));
        assert_eq!(seq[2], (&7, &6));
        assert_eq!(seq[3], (&8, &10));
    }

    #[test]
    fn test_sort() {
        let mut vec_map = VecMap::<u32, u64, 4>::default();
        assert_eq!(*vec_map.get_mut_or_insert_with(&9, || 5).unwrap(), 5);
        assert_eq!(*vec_map.get_mut_or_insert_with(&3, || 6).unwrap(), 6);
        assert_eq!(*vec_map.get_mut_or_insert_with(&7, || 7).unwrap(), 7);
        assert_eq!(*vec_map.get_mut_or_insert_with(&1, || 10).unwrap(), 10);

        let seq: alloc::vec::Vec<_> = vec_map.iter().collect();
        assert_eq!(seq.len(), 4);
        assert_eq!(seq[0], (&9, &5));
        assert_eq!(seq[1], (&3, &6));
        assert_eq!(seq[2], (&7, &7));
        assert_eq!(seq[3], (&1, &10));

        vec_map.sort();

        let seq: alloc::vec::Vec<_> = vec_map.iter().collect();
        assert_eq!(seq.len(), 4);
        assert_eq!(seq[0], (&1, &10));
        assert_eq!(seq[1], (&3, &6));
        assert_eq!(seq[2], (&7, &7));
        assert_eq!(seq[3], (&9, &5));

        vec_map.sort();

        let seq: alloc::vec::Vec<_> = vec_map.iter().collect();
        assert_eq!(seq.len(), 4);
        assert_eq!(seq[0], (&1, &10));
        assert_eq!(seq[1], (&3, &6));
        assert_eq!(seq[2], (&7, &7));
        assert_eq!(seq[3], (&9, &5));
    }
}
