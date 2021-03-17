// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A simple, safe LRU cache implementation.
//!
//! This design tradeoffs some memory usage in favor of faster item lookup times
//! by storing an additional HashMap that allows quickly checking if a key is
//! already in the cache.

use crate::HashMap;
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::hash::Hash;

/// LRU Cache.
pub struct LruCache<K, V> {
    /// Entries currently in cache.
    entries: Vec<Option<(Arc<K>, V)>>,

    /// A map of keys -> their index in the `entries` vector, used to speed up
    /// lookups.
    key_to_entry_index: HashMap<Arc<K>, usize>,

    /// Indexes of used entries inside the `entries` array. Sorted from newest
    /// to oldest.
    used_indexes: VecDeque<usize>,

    /// Indexes of free entries in the `entries` array.
    free_indexes: VecDeque<usize>,
}

impl<K: PartialEq + Eq + Hash, V> LruCache<K, V> {
    /// Create a new LRU cache instance.
    pub fn new(capacity: usize) -> Self {
        let mut entries = Vec::with_capacity(capacity);
        let mut free_indexes = VecDeque::with_capacity(capacity);
        for i in 0..capacity {
            entries.push(None);
            free_indexes.push_back(i);
        }

        Self {
            entries,
            key_to_entry_index: HashMap::default(),
            used_indexes: VecDeque::with_capacity(capacity),
            free_indexes,
        }
    }

    /// Returns the number of elements in the cache.
    pub fn len(&self) -> usize {
        assert_eq!(self.used_indexes.len(), self.key_to_entry_index.len());
        self.used_indexes.len()
    }

    /// Returns a bool indicating whether the cache is empty or not.
    pub fn is_empty(&self) -> bool {
        self.used_indexes.is_empty()
    }

    /// Returns a bool indicating whether the cache is full or not.
    pub fn is_full(&self) -> bool {
        self.free_indexes.is_empty()
    }

    /// Checks if a given key is already in the cache, without touching it.
    pub fn contains(&self, key: &K) -> bool {
        self.key_to_entry_index.contains_key(key)
    }

    /// Clears the cache.
    pub fn clear(&mut self) {
        while let Some(used_index) = self.used_indexes.pop_front() {
            self.entries[used_index] = None;
            self.key_to_entry_index.clear();
            self.free_indexes.push_front(used_index);
        }
    }

    /// Insert a given key in the cache.
    ///
    /// This item becomes the front (most-recently-used) item in the cache.  If
    /// the cache is full, the back (least-recently-used) item will be
    /// removed. If an item with the given key already existed, its value is
    /// replaced with the new value and the old value is returned.
    pub fn put(&mut self, key: K, val: V) -> Option<V> {
        let key = Arc::new(key);

        if let Some(used_index) = self.search_used(&key) {
            let entry_idx = self.used_indexes[used_index];

            // Grab the old entry so that we could return the old value.
            let prev_entry = self.entries[entry_idx].take();

            // Store the new entry in place of the old one.
            self.entries[entry_idx] = Some((key.clone(), val));
            self.key_to_entry_index.insert(key, entry_idx);

            // Move the entry to the front of the used list.
            self.used_indexes.remove(used_index);
            self.used_indexes.push_front(entry_idx);

            return prev_entry.map(|(_k, v)| v);
        }

        // Entry not present in cache, see if we have a free slot for it.
        if let Some(free_index) = self.free_indexes.pop_back() {
            assert!(self.entries[free_index].is_none());

            // Store the new entry and put it at the front of the used list.
            self.entries[free_index] = Some((key.clone(), val));
            self.key_to_entry_index.insert(key, free_index);

            self.used_indexes.push_front(free_index);
        } else {
            // No free entries.
            // Get the index of the oldest entry in the cache, and remove it from the used
            // list.
            let index = self
                .used_indexes
                .pop_back()
                .expect("no free indexes and no used indexes!?");
            assert!(self.entries[index].is_some());

            self.key_to_entry_index
                .remove(&self.entries[index].as_ref().unwrap().0);

            // Replace it with the new entry and put at at the front.
            self.entries[index] = Some((key.clone(), val));
            self.key_to_entry_index.insert(key, index);
            self.used_indexes.push_front(index);
        }

        None
    }

    /// Returns a reference to the value of the key in the cache or `None` if it
    /// is not present in the cache. Moves the key to the head of the LRU list
    /// if it exists.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        self.get_mut(key).map(|x| &*x)
    }

    /// Returns a mutable reference to the value of the key in the cache or
    /// `None` if it is not present in the cache. Moves the key to the head
    /// of the LRU list if it exists.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        // Try and locate key.
        let used_index = self.search_used(key)?;

        // If we located the key, move it to the front of the used list and return a
        // reference to its value.
        let entry_index = self.used_indexes[used_index];
        self.used_indexes.remove(used_index);
        self.used_indexes.push_front(entry_index);
        self.entries[entry_index].as_mut().map(|(_k, v)| v)
    }

    /// Returns a reference to the value corresponding to the key in the cache
    /// or `None` if it is not present in the cache. Unlike `get`, `peek`
    /// does not update the LRU list so the key's position will be
    /// unchanged.
    pub fn peek(&self, key: &K) -> Option<&V> {
        // Try and locate key.
        let entry_index = self.key_to_entry_index.get(key)?;

        // If we located the key, return the matching value.
        self.entries[*entry_index].as_ref().map(|(_k, v)| v)
    }

    /// Removes and returns the value corresponding to the key from the cache or
    /// `None` if it does not exist.
    pub fn pop(&mut self, key: &K) -> Option<V> {
        let used_index = self.search_used(key)?;

        let entry_idx = self.used_indexes[used_index];
        let entry = self.entries[entry_idx].take();

        self.used_indexes.remove(used_index);
        self.free_indexes.push_front(entry_idx);

        if let Some((k, v)) = entry {
            self.key_to_entry_index.remove(&k);
            Some(v)
        } else {
            None
        }
    }

    /// Iterate over the contents of this cache.
    pub fn iter(&self) -> LruCacheIterator<K, V> {
        LruCacheIterator {
            pos: 0,
            cache: self,
        }
    }

    /// Iterate over the contents of this cache.
    pub fn iter_mut(&mut self) -> LruCacheMutIterator<K, V> {
        LruCacheMutIterator {
            pos: 0,
            cache: self,
        }
    }

    /// Search for a given key in the cache, returing its index in the used
    /// array if found.
    fn search_used(&self, key: &K) -> Option<usize> {
        // Quick out if we do not have the key.
        if !self.key_to_entry_index.contains_key(key) {
            return None;
        }

        for i in 0..self.used_indexes.len() {
            let entry_idx = self.used_indexes[i];
            if let Some((key2, _val2)) = &self.entries[entry_idx] {
                if key == key2.as_ref() {
                    return Some(i);
                }
            }
        }

        None
    }
}

/// Iterator over values in an LruCache, from most-recently-used to
/// least-recently-used.
pub struct LruCacheIterator<'a, K: 'a, V: 'a> {
    cache: &'a LruCache<K, V>,
    pos: usize,
}

impl<'a, K, V> Iterator for LruCacheIterator<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.pos == self.cache.used_indexes.len() {
                return None;
            }

            let entry_index = self.cache.used_indexes[self.pos];
            let entry = &self.cache.entries[entry_index];

            self.pos += 1;

            if let Some((ref k, ref v)) = entry {
                return Some((&k, &v));
            }
        }
    }
}

/// Mutable Iterator over values in an LruCache, from most-recently-used to
/// least-recently-used.
pub struct LruCacheMutIterator<'a, K: 'a, V: 'a> {
    cache: &'a mut LruCache<K, V>,
    pos: usize,
}

impl<'a, K, V> Iterator for LruCacheMutIterator<'a, K, V> {
    type Item = (&'a K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.pos == self.cache.used_indexes.len() {
                return None;
            }

            let entry_index = self.cache.used_indexes[self.pos];

            // Hack to get around the borrow checker. The borrow checker would prevent us
            // from returning a mutable reference to an entry, since in order to
            // get the entry we need to hold a reference to the Option inside
            // `self.cache.entries`. However, since we're holding that
            // reference, we will then be denied from creating another mutable
            // reference.
            // This code is safe because the list of entries is not going to be modified
            // during iteration, since a mutable reference to the LruCache is
            // held by the iterator.
            let entry =
                unsafe { &mut *(&mut self.cache.entries[entry_index] as *mut Option<(Arc<K>, V)>) };

            self.pos += 1;

            if let Some((ref k, ref mut v)) = entry.as_mut() {
                return Some((&k, v));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests taken from https://raw.githubusercontent.com/jeromefroe/lru-rs/master/src/lib.rs @ a11d47ddc7ab86ff07e2308e96fa0a03bcc3f385

    use super::LruCache;
    use core::fmt::Debug;

    fn assert_opt_eq<V: PartialEq + Debug>(opt: Option<&V>, v: V) {
        assert!(opt.is_some());
        assert_eq!(opt.unwrap(), &v);
    }

    fn assert_opt_eq_mut<V: PartialEq + Debug>(opt: Option<&mut V>, v: V) {
        assert!(opt.is_some());
        assert_eq!(opt.unwrap(), &v);
    }

    fn assert_opt_eq_tuple<K: PartialEq + Debug, V: PartialEq + Debug>(
        opt: Option<(&K, &V)>,
        kv: (K, V),
    ) {
        assert!(opt.is_some());
        let res = opt.unwrap();
        assert_eq!(res.0, &kv.0);
        assert_eq!(res.1, &kv.1);
    }

    fn assert_opt_eq_mut_tuple<K: PartialEq + Debug, V: PartialEq + Debug>(
        opt: Option<(&K, &mut V)>,
        kv: (K, V),
    ) {
        assert!(opt.is_some());
        let res = opt.unwrap();
        assert_eq!(res.0, &kv.0);
        assert_eq!(res.1, &kv.1);
    }

    #[test]
    fn test_put_and_get() {
        let mut cache = LruCache::new(2);
        assert!(cache.is_empty());

        assert_eq!(cache.put("apple", "red"), None);
        assert_eq!(cache.put("banana", "yellow"), None);

        assert_eq!(cache.len(), 2);
        assert!(!cache.is_empty());
        assert_opt_eq(cache.get(&"apple"), "red");
        assert_opt_eq(cache.get(&"banana"), "yellow");
    }

    #[test]
    fn test_put_and_get_mut() {
        let mut cache = LruCache::new(2);

        cache.put("apple", "red");
        cache.put("banana", "yellow");

        assert_eq!(cache.len(), 2);
        assert_opt_eq_mut(cache.get_mut(&"apple"), "red");
        assert_opt_eq_mut(cache.get_mut(&"banana"), "yellow");
    }

    #[test]
    fn test_get_mut_and_update() {
        let mut cache = LruCache::new(2);

        cache.put("apple", 1);
        cache.put("banana", 3);

        {
            let v = cache.get_mut(&"apple").unwrap();
            *v = 4;
        }

        assert_eq!(cache.len(), 2);
        assert_opt_eq_mut(cache.get_mut(&"apple"), 4);
        assert_opt_eq_mut(cache.get_mut(&"banana"), 3);
    }

    #[test]
    fn test_put_update() {
        let mut cache = LruCache::new(1);

        assert_eq!(cache.put("apple", "red"), None);
        assert_eq!(cache.put("apple", "green"), Some("red"));

        assert_eq!(cache.len(), 1);
        assert_opt_eq(cache.get(&"apple"), "green");
    }

    #[test]
    fn test_put_removes_oldest() {
        let mut cache = LruCache::new(2);

        assert_eq!(cache.len(), 0);
        assert_eq!(cache.put("apple", "red"), None);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.put("banana", "yellow"), None);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.put("pear", "green"), None);
        assert_eq!(cache.len(), 2);

        assert!(cache.get(&"apple").is_none());
        assert_opt_eq(cache.get(&"banana"), "yellow");
        assert_opt_eq(cache.get(&"pear"), "green");

        // Even though we inserted "apple" into the cache earlier it has since been
        // removed from the cache so there is no current value for `put` to
        // return.
        assert_eq!(cache.put("apple", "green"), None);
        assert_eq!(cache.put("tomato", "red"), None);

        assert!(cache.get(&"pear").is_none());
        assert_opt_eq(cache.get(&"apple"), "green");
        assert_opt_eq(cache.get(&"tomato"), "red");
    }

    #[test]
    fn test_contains() {
        let mut cache = LruCache::new(2);

        cache.put("apple", "red");
        cache.put("banana", "yellow");
        cache.put("pear", "green");

        assert!(!cache.contains(&"apple"));
        assert!(cache.contains(&"banana"));
        assert!(cache.contains(&"pear"));
    }

    #[test]
    fn test_iter_forwards() {
        let mut cache = LruCache::new(4);
        cache.put("a", 1);
        cache.put("b", 2);
        cache.put("c", 3);
        cache.put("d", 4);

        let mut iter = cache.iter();
        assert_opt_eq_tuple(iter.next(), ("d", 4));
        assert_opt_eq_tuple(iter.next(), ("c", 3));
        assert_opt_eq_tuple(iter.next(), ("b", 2));
        assert_opt_eq_tuple(iter.next(), ("a", 1));
        assert_eq!(iter.next(), None);

        // Get "b", that should move it to the front of the list.
        assert_opt_eq(cache.get(&"b"), 2);

        let mut iter = cache.iter();
        assert_opt_eq_tuple(iter.next(), ("b", 2));
        assert_opt_eq_tuple(iter.next(), ("d", 4));
        assert_opt_eq_tuple(iter.next(), ("c", 3));
        assert_opt_eq_tuple(iter.next(), ("a", 1));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_iter_mut_forwards() {
        let mut cache = LruCache::new(4);
        cache.put("a", 1);
        cache.put("b", 2);
        cache.put("c", 3);
        cache.put("d", 4);

        let mut iter = cache.iter_mut();
        assert_opt_eq_mut_tuple(iter.next(), ("d", 4));
        assert_opt_eq_mut_tuple(iter.next(), ("c", 3));
        assert_opt_eq_mut_tuple(iter.next(), ("b", 2));
        assert_opt_eq_mut_tuple(iter.next(), ("a", 1));
        assert_eq!(iter.next(), None);

        // Get "b", that should move it to the front of the list.
        assert_opt_eq(cache.get(&"b"), 2);

        let mut iter = cache.iter_mut();
        assert_opt_eq_mut_tuple(iter.next(), ("b", 2));
        assert_opt_eq_mut_tuple(iter.next(), ("d", 4));
        assert_opt_eq_mut_tuple(iter.next(), ("c", 3));
        assert_opt_eq_mut_tuple(iter.next(), ("a", 1));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_iter_mut_mutates() {
        let mut cache = LruCache::new(4);
        cache.put("a", 1);
        cache.put("b", 2);
        cache.put("c", 3);
        cache.put("d", 4);

        for (i, (_key, val)) in cache.iter_mut().enumerate() {
            assert_eq!(4 - i, *val);
            *val = 100 + i;
        }

        let mut iter = cache.iter_mut();
        assert_opt_eq_mut_tuple(iter.next(), ("d", 100));
        assert_opt_eq_mut_tuple(iter.next(), ("c", 101));
        assert_opt_eq_mut_tuple(iter.next(), ("b", 102));
        assert_opt_eq_mut_tuple(iter.next(), ("a", 103));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_pop() {
        let mut cache = LruCache::new(2);

        cache.put("apple", "red");
        cache.put("banana", "yellow");

        assert_eq!(cache.len(), 2);
        assert_opt_eq(cache.get(&"apple"), "red");
        assert_opt_eq(cache.get(&"banana"), "yellow");

        let popped = cache.pop(&"apple");
        assert!(popped.is_some());
        assert_eq!(popped.unwrap(), "red");
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&"apple").is_none());
        assert_opt_eq(cache.get(&"banana"), "yellow");
    }

    #[test]
    fn test_that_pop_actually_detaches_node() {
        let mut cache = LruCache::new(5);

        cache.put("a", 1);
        cache.put("b", 2);
        cache.put("c", 3);
        cache.put("d", 4);
        cache.put("e", 5);

        assert!(cache.contains(&"c"));
        assert_eq!(cache.pop(&"c"), Some(3));
        assert!(!cache.contains(&"c"));

        cache.put("f", 6);

        let mut iter = cache.iter();
        assert_opt_eq_tuple(iter.next(), ("f", 6));
        assert_opt_eq_tuple(iter.next(), ("e", 5));
        assert_opt_eq_tuple(iter.next(), ("d", 4));
        assert_opt_eq_tuple(iter.next(), ("b", 2));
        assert_opt_eq_tuple(iter.next(), ("a", 1));
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_peek() {
        let mut cache = LruCache::new(2);

        cache.put("apple", "red");
        cache.put("banana", "yellow");

        assert_opt_eq(cache.peek(&"banana"), "yellow");
        assert_opt_eq(cache.peek(&"apple"), "red");

        cache.put("pear", "green");

        assert!(cache.peek(&"apple").is_none());
        assert_opt_eq(cache.peek(&"banana"), "yellow");
        assert_opt_eq(cache.peek(&"pear"), "green");
    }

    #[test]
    fn test_clear() {
        let mut cache = LruCache::new(2);

        cache.put("apple", "red");
        cache.put("banana", "yellow");

        assert_eq!(cache.len(), 2);
        assert_opt_eq(cache.get(&"apple"), "red");
        assert_opt_eq(cache.get(&"banana"), "yellow");

        cache.clear();
        assert_eq!(cache.len(), 0);
    }
}
