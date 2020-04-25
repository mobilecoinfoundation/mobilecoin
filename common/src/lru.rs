// Taken from https://raw.githubusercontent.com/jeromefroe/lru-rs/master/src/lib.rs @ a11d47ddc7ab86ff07e2308e96fa0a03bcc3f385
// We copied this into our repository because for no_std builds we need the hashbrown feature, but
// without ahash. Without introducing all of hashbrown's features into the lru crate, there is no
// way to include hashbrown in our desired configuration.
// The code was modified to always enable the hashbrown/nightly features.

// MIT License

// Copyright (c) 2016 Jerome Froelich

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNpubESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! An implementation of a LRU cache. The cache supports `get`, `get_mut`, `put`,
//! and `pop` operations, all of which are O(1). This crate was heavily influenced
//! by the [LRU Cache implementation in an earlier version of Rust's std::collections crate](https://doc.rust-lang.org/0.12.0/std/collections/lru_cache/struct.LruCache.html).
//!
//! ## Example
//!
//! ```rust,no_run
//!
//! use mc_common::LruCache;
//!
//! fn main() {
//!         let mut cache = LruCache::new(2);
//!         cache.put("apple", 3);
//!         cache.put("banana", 2);
//!
//!         assert_eq!(*cache.get(&"apple").unwrap(), 3);
//!         assert_eq!(*cache.get(&"banana").unwrap(), 2);
//!         assert!(cache.get(&"pear").is_none());
//!
//!         assert_eq!(cache.put("banana", 4), Some(2));
//!         assert_eq!(cache.put("pear", 5), None);
//!
//!         assert_eq!(*cache.get(&"pear").unwrap(), 5);
//!         assert_eq!(*cache.get(&"banana").unwrap(), 4);
//!         assert!(cache.get(&"apple").is_none());
//!
//!         {
//!             let v = cache.get_mut(&"banana").unwrap();
//!             *v = 6;
//!         }
//!
//!         assert_eq!(*cache.get(&"banana").unwrap(), 6);
//! }
//! ```

// This file contains third-party code that doesn't pass clippy. For the sake of keeping the changes to a minimum, clippy is being skipped.
// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

use alloc::{borrow::Borrow, boxed::Box};
use core::{
    fmt,
    hash::{BuildHasher, Hash, Hasher},
    iter::FusedIterator,
    marker::PhantomData,
    mem, ptr, usize,
};

use hashbrown::HashMap;

// Struct used to hold a reference to a key
#[doc(hidden)]
pub struct KeyRef<K> {
    k: *const K,
}

impl<K: Hash> Hash for KeyRef<K> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        unsafe { (*self.k).hash(state) }
    }
}

impl<K: PartialEq> PartialEq for KeyRef<K> {
    fn eq(&self, other: &KeyRef<K>) -> bool {
        unsafe { (*self.k).eq(&*other.k) }
    }
}

impl<K: Eq> Eq for KeyRef<K> {}

#[doc(hidden)]
pub auto trait NotKeyRef {}

impl<K> !NotKeyRef for KeyRef<K> {}

impl<K, D> Borrow<D> for KeyRef<K>
where
    K: Borrow<D>,
    D: NotKeyRef + ?Sized,
{
    fn borrow(&self) -> &D {
        unsafe { (&*self.k) }.borrow()
    }
}

// Struct used to hold a key value pair. Also contains references to previous and next entries
// so we can maintain the entries in a linked list ordered by their use.
struct LruEntry<K, V> {
    key: K,
    val: V,
    prev: *mut LruEntry<K, V>,
    next: *mut LruEntry<K, V>,
}

impl<K, V> LruEntry<K, V> {
    fn new(key: K, val: V) -> Self {
        LruEntry {
            key,
            val,
            prev: ptr::null_mut(),
            next: ptr::null_mut(),
        }
    }
}

pub type DefaultHasher = crate::hasher_builder::HasherBuilder;

/// An LRU Cache
pub struct LruCache<K, V, S = DefaultHasher> {
    map: HashMap<KeyRef<K>, Box<LruEntry<K, V>>, S>,
    cap: usize,

    // head and tail are sigil nodes to faciliate inserting entries
    head: *mut LruEntry<K, V>,
    tail: *mut LruEntry<K, V>,
}

impl<K: Hash + Eq, V> LruCache<K, V> {
    /// Creates a new LRU Cache that holds at most `cap` items.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache: LruCache<isize, &str> = LruCache::new(10);
    /// ```
    pub fn new(cap: usize) -> LruCache<K, V> {
        LruCache::construct(
            cap,
            HashMap::with_capacity_and_hasher(cap, DefaultHasher::default()),
        )
    }

    /// Creates a new LRU Cache that never automatically evicts items.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache: LruCache<isize, &str> = LruCache::unbounded();
    /// ```
    pub fn unbounded() -> LruCache<K, V> {
        LruCache::construct(usize::MAX, HashMap::default())
    }
}

impl<K: Hash + Eq, V, S: BuildHasher> LruCache<K, V, S> {
    /// Creates a new LRU Cache that holds at most `cap` items and
    /// uses the providedash builder to hash keys.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::lru::{LruCache, DefaultHasher};
    ///
    /// let s = DefaultHasher::default();
    /// let mut cache: LruCache<isize, &str> = LruCache::with_hasher(10, s);
    /// ```
    pub fn with_hasher(cap: usize, hash_builder: S) -> LruCache<K, V, S> {
        LruCache::construct(cap, HashMap::with_capacity_and_hasher(cap, hash_builder))
    }

    /// Creates a new LRU Cache with the given capacity.
    fn construct(cap: usize, map: HashMap<KeyRef<K>, Box<LruEntry<K, V>>, S>) -> LruCache<K, V, S> {
        // NB: The compiler warns that cache does not need to be marked as mutable if we
        // declare it as such since we only mutate it inside the unsafe block.
        let cache = LruCache {
            map,
            cap,
            head: unsafe { Box::into_raw(Box::new(mem::MaybeUninit::uninit().assume_init())) },
            tail: unsafe { Box::into_raw(Box::new(mem::MaybeUninit::uninit().assume_init())) },
        };

        unsafe {
            (*cache.head).next = cache.tail;
            (*cache.tail).prev = cache.head;
        }

        cache
    }

    /// Puts a key-value pair into cache. If the key already exists in the cache, then it updates
    /// the key's value and returns the old value. Otherwise, `None` is returned.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache = LruCache::new(2);
    ///
    /// assert_eq!(None, cache.put(1, "a"));
    /// assert_eq!(None, cache.put(2, "b"));
    /// assert_eq!(Some("b"), cache.put(2, "beta"));
    ///
    /// assert_eq!(cache.get(&1), Some(&"a"));
    /// assert_eq!(cache.get(&2), Some(&"beta"));
    /// ```
    pub fn put(&mut self, k: K, mut v: V) -> Option<V> {
        let node_ptr = self.map.get_mut(&KeyRef { k: &k }).map(|node| {
            let node_ptr: *mut LruEntry<K, V> = &mut **node;
            node_ptr
        });

        match node_ptr {
            Some(node_ptr) => {
                // if the key is already in the cache just update its value and move it to the
                // front of the list
                unsafe { mem::swap(&mut v, &mut (*node_ptr).val) }
                self.detach(node_ptr);
                self.attach(node_ptr);
                Some(v)
            }
            None => {
                let mut node = if self.len() == self.cap() {
                    // if the cache is full, remove the last entry so we can use it for the new key
                    let old_key = KeyRef {
                        k: unsafe { &(*(*self.tail).prev).key },
                    };
                    let mut old_node = self.map.remove(&old_key).unwrap();

                    old_node.key = k;
                    old_node.val = v;

                    let node_ptr: *mut LruEntry<K, V> = &mut *old_node;
                    self.detach(node_ptr);

                    old_node
                } else {
                    // if the cache is not full allocate a new LruEntry
                    Box::new(LruEntry::new(k, v))
                };

                let node_ptr: *mut LruEntry<K, V> = &mut *node;
                self.attach(node_ptr);

                let keyref = unsafe { &(*node_ptr).key };
                self.map.insert(KeyRef { k: keyref }, node);
                None
            }
        }
    }

    /// Returns a reference to the value of the key in the cache or `None` if it is not
    /// present in the cache. Moves the key to the head of the LRU list if it exists.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache = LruCache::new(2);
    ///
    /// cache.put(1, "a");
    /// cache.put(2, "b");
    /// cache.put(2, "c");
    /// cache.put(3, "d");
    ///
    /// assert_eq!(cache.get(&1), None);
    /// assert_eq!(cache.get(&2), Some(&"c"));
    /// assert_eq!(cache.get(&3), Some(&"d"));
    /// ```
    pub fn get<'a, Q>(&'a mut self, k: &Q) -> Option<&'a V>
    where
        KeyRef<K>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        if let Some(node) = self.map.get_mut(k) {
            let node_ptr: *mut LruEntry<K, V> = &mut **node;

            self.detach(node_ptr);
            self.attach(node_ptr);

            Some(unsafe { &(*node_ptr).val })
        } else {
            None
        }
    }

    /// Returns a mutable reference to the value of the key in the cache or `None` if it
    /// is not present in the cache. Moves the key to the head of the LRU list if it exists.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache = LruCache::new(2);
    ///
    /// cache.put("apple", 8);
    /// cache.put("banana", 4);
    /// cache.put("banana", 6);
    /// cache.put("pear", 2);
    ///
    /// assert_eq!(cache.get_mut(&"apple"), None);
    /// assert_eq!(cache.get_mut(&"banana"), Some(&mut 6));
    /// assert_eq!(cache.get_mut(&"pear"), Some(&mut 2));
    /// ```
    pub fn get_mut<'a, Q>(&'a mut self, k: &Q) -> Option<&'a mut V>
    where
        KeyRef<K>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        if let Some(node) = self.map.get_mut(k) {
            let node_ptr: *mut LruEntry<K, V> = &mut **node;

            self.detach(node_ptr);
            self.attach(node_ptr);

            Some(unsafe { &mut (*node_ptr).val })
        } else {
            None
        }
    }

    /// Returns a reference to the value corresponding to the key in the cache or `None` if it is
    /// not present in the cache. Unlike `get`, `peek` does not update the LRU list so the key's
    /// position will be unchanged.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache = LruCache::new(2);
    ///
    /// cache.put(1, "a");
    /// cache.put(2, "b");
    ///
    /// assert_eq!(cache.peek(&1), Some(&"a"));
    /// assert_eq!(cache.peek(&2), Some(&"b"));
    /// ```
    pub fn peek<'a, Q>(&'a self, k: &Q) -> Option<&'a V>
    where
        KeyRef<K>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        match self.map.get(k) {
            None => None,
            Some(node) => Some(&node.val),
        }
    }

    /// Returns a mutable reference to the value corresponding to the key in the cache or `None`
    /// if it is not present in the cache. Unlike `get_mut`, `peek_mut` does not update the LRU
    /// list so the key's position will be unchanged.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache = LruCache::new(2);
    ///
    /// cache.put(1, "a");
    /// cache.put(2, "b");
    ///
    /// assert_eq!(cache.peek_mut(&1), Some(&mut "a"));
    /// assert_eq!(cache.peek_mut(&2), Some(&mut "b"));
    /// ```
    pub fn peek_mut<'a, Q>(&'a mut self, k: &Q) -> Option<&'a mut V>
    where
        KeyRef<K>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        match self.map.get_mut(k) {
            None => None,
            Some(node) => Some(&mut node.val),
        }
    }

    /// Returns the value corresponding to the least recently used item or `None` if the
    /// cache is empty. Like `peek`, `peek_lru` does not update the LRU list so the item's
    /// position will be unchanged.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache = LruCache::new(2);
    ///
    /// cache.put(1, "a");
    /// cache.put(2, "b");
    ///
    /// assert_eq!(cache.peek_lru(), Some((&1, &"a")));
    /// ```
    pub fn peek_lru<'a>(&'a self) -> Option<(&'a K, &'a V)> {
        if self.len() == 0 {
            return None;
        }

        let (key, val);
        unsafe {
            let node = (*self.tail).prev;
            key = &(*node).key;
            val = &(*node).val;
        }

        Some((key, val))
    }

    /// Returns a bool indicating whether the given key is in the cache. Does not update the
    /// LRU list.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache = LruCache::new(2);
    ///
    /// cache.put(1, "a");
    /// cache.put(2, "b");
    /// cache.put(3, "c");
    ///
    /// assert!(!cache.contains(&1));
    /// assert!(cache.contains(&2));
    /// assert!(cache.contains(&3));
    /// ```
    pub fn contains<Q>(&self, k: &Q) -> bool
    where
        KeyRef<K>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.contains_key(k)
    }

    /// Removes and returns the value corresponding to the key from the cache or
    /// `None` if it does not exist.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache = LruCache::new(2);
    ///
    /// cache.put(2, "a");
    ///
    /// assert_eq!(cache.pop(&1), None);
    /// assert_eq!(cache.pop(&2), Some("a"));
    /// assert_eq!(cache.pop(&2), None);
    /// assert_eq!(cache.len(), 0);
    /// ```
    pub fn pop<Q>(&mut self, k: &Q) -> Option<V>
    where
        KeyRef<K>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        match self.map.remove(&k) {
            None => None,
            Some(mut old_node) => {
                let node_ptr: *mut LruEntry<K, V> = &mut *old_node;
                self.detach(node_ptr);
                Some(old_node.val)
            }
        }
    }

    /// Removes and returns the key and value corresponding to the least recently
    /// used item or `None` if the cache is empty.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache = LruCache::new(2);
    ///
    /// cache.put(2, "a");
    /// cache.put(3, "b");
    /// cache.put(4, "c");
    /// cache.get(&3);
    ///
    /// assert_eq!(cache.pop_lru(), Some((4, "c")));
    /// assert_eq!(cache.pop_lru(), Some((3, "b")));
    /// assert_eq!(cache.pop_lru(), None);
    /// assert_eq!(cache.len(), 0);
    /// ```
    pub fn pop_lru(&mut self) -> Option<(K, V)> {
        let node = self.remove_last()?;
        // N.B.: Can't destructure directly because of https://github.com/rust-lang/rust/issues/28536
        let node = *node;
        let LruEntry { key, val, .. } = node;
        Some((key, val))
    }

    /// Returns the number of key-value pairs that are currently in the the cache.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache = LruCache::new(2);
    /// assert_eq!(cache.len(), 0);
    ///
    /// cache.put(1, "a");
    /// assert_eq!(cache.len(), 1);
    ///
    /// cache.put(2, "b");
    /// assert_eq!(cache.len(), 2);
    ///
    /// cache.put(3, "c");
    /// assert_eq!(cache.len(), 2);
    /// ```
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns a bool indicating whether the cache is empty or not.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache = LruCache::new(2);
    /// assert!(cache.is_empty());
    ///
    /// cache.put(1, "a");
    /// assert!(!cache.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.map.len() == 0
    }

    /// Returns the maximum number of key-value pairs the cache can hold.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache: LruCache<isize, &str> = LruCache::new(2);
    /// assert_eq!(cache.cap(), 2);
    /// ```
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Resizes the cache. If the new capacity is smaller than the size of the current
    /// cache any entries past the new capacity are discarded.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache: LruCache<isize, &str> = LruCache::new(2);
    ///
    /// cache.put(1, "a");
    /// cache.put(2, "b");
    /// cache.resize(4);
    /// cache.put(3, "c");
    /// cache.put(4, "d");
    ///
    /// assert_eq!(cache.len(), 4);
    /// assert_eq!(cache.get(&1), Some(&"a"));
    /// assert_eq!(cache.get(&2), Some(&"b"));
    /// assert_eq!(cache.get(&3), Some(&"c"));
    /// assert_eq!(cache.get(&4), Some(&"d"));
    /// ```
    pub fn resize(&mut self, cap: usize) {
        // return early if capacity doesn't change
        if cap == self.cap {
            return;
        }

        while self.map.len() > cap {
            self.remove_last();
        }
        self.map.shrink_to_fit();

        self.cap = cap;
    }

    /// Clears the contents of the cache.
    ///
    /// # Example
    ///
    /// ```
    /// use mc_common::LruCache;
    /// let mut cache: LruCache<isize, &str> = LruCache::new(2);
    /// assert_eq!(cache.len(), 0);
    ///
    /// cache.put(1, "a");
    /// assert_eq!(cache.len(), 1);
    ///
    /// cache.put(2, "b");
    /// assert_eq!(cache.len(), 2);
    ///
    /// cache.clear();
    /// assert_eq!(cache.len(), 0);
    /// ```
    pub fn clear(&mut self) {
        loop {
            match self.remove_last() {
                Some(_) => (),
                None => break,
            }
        }
    }

    /// An iterator visiting all entries in order. The iterator element type is `(&'a K, &'a V)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use mc_common::LruCache;
    ///
    /// let mut cache = LruCache::new(3);
    /// cache.put("a", 1);
    /// cache.put("b", 2);
    /// cache.put("c", 3);
    ///
    /// for (key, val) in cache.iter() {
    ///     println!("key: {} val: {}", key, val);
    /// }
    /// ```
    pub fn iter<'a>(&'a self) -> Iter<'a, K, V> {
        Iter {
            len: self.len(),
            ptr: unsafe { (*self.head).next },
            end: unsafe { (*self.tail).prev },
            phantom: PhantomData,
        }
    }

    /// An iterator visiting all entries in order, giving a mutable reference on V.
    /// The iterator element type is `(&'a K, &'a mut V)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use mc_common::LruCache;
    ///
    /// struct HddBlock {
    ///     dirty: bool,
    ///     data: [u8; 512]
    /// }
    ///
    /// let mut cache = LruCache::new(3);
    /// cache.put(0, HddBlock { dirty: false, data: [0x00; 512]});
    /// cache.put(1, HddBlock { dirty: true,  data: [0x55; 512]});
    /// cache.put(2, HddBlock { dirty: true,  data: [0x77; 512]});
    ///
    /// // write dirty blocks to disk.
    /// for (block_id, block) in cache.iter_mut() {
    ///     if block.dirty {
    ///         // write block to disk
    ///         block.dirty = false
    ///     }
    /// }
    /// ```
    pub fn iter_mut<'a>(&'a mut self) -> IterMut<'a, K, V> {
        IterMut {
            len: self.len(),
            ptr: unsafe { (*self.head).next },
            end: unsafe { (*self.tail).prev },
            phantom: PhantomData,
        }
    }

    fn remove_last(&mut self) -> Option<Box<LruEntry<K, V>>> {
        let prev;
        unsafe { prev = (*self.tail).prev }
        if prev != self.head {
            let old_key = KeyRef {
                k: unsafe { &(*(*self.tail).prev).key },
            };
            let mut old_node = self.map.remove(&old_key).unwrap();
            let node_ptr: *mut LruEntry<K, V> = &mut *old_node;
            self.detach(node_ptr);
            Some(old_node)
        } else {
            None
        }
    }

    fn detach(&mut self, node: *mut LruEntry<K, V>) {
        unsafe {
            (*(*node).prev).next = (*node).next;
            (*(*node).next).prev = (*node).prev;
        }
    }

    fn attach(&mut self, node: *mut LruEntry<K, V>) {
        unsafe {
            (*node).next = (*self.head).next;
            (*node).prev = self.head;
            (*self.head).next = node;
            (*(*node).next).prev = node;
        }
    }
}

impl<K, V, S> Drop for LruCache<K, V, S> {
    fn drop(&mut self) {
        // Prevent compiler from trying to drop the un-initialized fields key and val in head
        // and tail
        unsafe {
            let head = *Box::from_raw(self.head);
            let tail = *Box::from_raw(self.tail);

            let LruEntry {
                key: head_key,
                val: head_val,
                ..
            } = head;
            let LruEntry {
                key: tail_key,
                val: tail_val,
                ..
            } = tail;

            mem::forget(head_key);
            mem::forget(head_val);
            mem::forget(tail_key);
            mem::forget(tail_val);
        }
    }
}

impl<'a, K: Hash + Eq, V, S: BuildHasher> IntoIterator for &'a LruCache<K, V, S> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    fn into_iter(self) -> Iter<'a, K, V> {
        self.iter()
    }
}

impl<'a, K: Hash + Eq, V, S: BuildHasher> IntoIterator for &'a mut LruCache<K, V, S> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = IterMut<'a, K, V>;

    fn into_iter(self) -> IterMut<'a, K, V> {
        self.iter_mut()
    }
}

// The compiler does not automatically derive Send and Sync for LruCache because it contains
// raw pointers. The raw pointers are safely encapsulated by LruCache though so we can
// implement Send and Sync for it below.
unsafe impl<K: Send, V: Send> Send for LruCache<K, V> {}
unsafe impl<K: Sync, V: Sync> Sync for LruCache<K, V> {}

impl<K: Hash + Eq, V> fmt::Debug for LruCache<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("LruCache")
            .field("len", &self.len())
            .field("cap", &self.cap())
            .finish()
    }
}

/// An iterator over the entries of a `LruCache`.
///
/// This `struct` is created by the [`iter`] method on [`LruCache`][`LruCache`]. See its
/// documentation for more.
///
/// [`iter`]: struct.LruCache.html#method.iter
/// [`LruCache`]: struct.LruCache.html
pub struct Iter<'a, K: 'a, V: 'a> {
    len: usize,

    ptr: *const LruEntry<K, V>,
    end: *const LruEntry<K, V>,

    phantom: PhantomData<&'a K>,
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<(&'a K, &'a V)> {
        if self.len == 0 {
            return None;
        }

        let key = unsafe { &(*self.ptr).key };
        let val = unsafe { &(*self.ptr).val };

        self.len -= 1;
        self.ptr = unsafe { (*self.ptr).next };

        Some((key, val))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len, Some(self.len))
    }

    fn count(self) -> usize {
        self.len
    }
}

impl<'a, K, V> DoubleEndedIterator for Iter<'a, K, V> {
    fn next_back(&mut self) -> Option<(&'a K, &'a V)> {
        if self.len == 0 {
            return None;
        }

        let key = unsafe { &(*self.end).key };
        let val = unsafe { &(*self.end).val };

        self.len -= 1;
        self.end = unsafe { (*self.end).prev };

        Some((key, val))
    }
}

impl<'a, K, V> ExactSizeIterator for Iter<'a, K, V> {}
impl<'a, K, V> FusedIterator for Iter<'a, K, V> {}

impl<'a, K, V> Clone for Iter<'a, K, V> {
    fn clone(&self) -> Iter<'a, K, V> {
        Iter {
            len: self.len,
            ptr: self.ptr,
            end: self.end,
            phantom: PhantomData,
        }
    }
}

// The compiler does not automatically derive Send and Sync for Iter because it contains
// raw pointers.
unsafe impl<'a, K: Send, V: Send> Send for Iter<'a, K, V> {}
unsafe impl<'a, K: Sync, V: Sync> Sync for Iter<'a, K, V> {}

/// An iterator over mutables entries of a `LruCache`.
///
/// This `struct` is created by the [`iter_mut`] method on [`LruCache`][`LruCache`]. See its
/// documentation for more.
///
/// [`iter_mut`]: struct.LruCache.html#method.iter_mut
/// [`LruCache`]: struct.LruCache.html
pub struct IterMut<'a, K: 'a, V: 'a> {
    len: usize,

    ptr: *mut LruEntry<K, V>,
    end: *mut LruEntry<K, V>,

    phantom: PhantomData<&'a K>,
}

impl<'a, K, V> Iterator for IterMut<'a, K, V> {
    type Item = (&'a K, &'a mut V);

    fn next(&mut self) -> Option<(&'a K, &'a mut V)> {
        if self.len == 0 {
            return None;
        }

        let key = unsafe { &(*self.ptr).key };
        let val = unsafe { &mut (*self.ptr).val };

        self.len -= 1;
        self.ptr = unsafe { (*self.ptr).next };

        Some((key, val))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len, Some(self.len))
    }

    fn count(self) -> usize {
        self.len
    }
}

impl<'a, K, V> DoubleEndedIterator for IterMut<'a, K, V> {
    fn next_back(&mut self) -> Option<(&'a K, &'a mut V)> {
        if self.len == 0 {
            return None;
        }

        let key = unsafe { &(*self.end).key };
        let val = unsafe { &mut (*self.end).val };

        self.len -= 1;
        self.end = unsafe { (*self.end).prev };

        Some((key, val))
    }
}

impl<'a, K, V> ExactSizeIterator for IterMut<'a, K, V> {}
impl<'a, K, V> FusedIterator for IterMut<'a, K, V> {}

// The compiler does not automatically derive Send and Sync for Iter because it contains
// raw pointers.
unsafe impl<'a, K: Send, V: Send> Send for IterMut<'a, K, V> {}
unsafe impl<'a, K: Sync, V: Sync> Sync for IterMut<'a, K, V> {}

#[cfg(test)]
mod tests {
    use super::LruCache;
    use core::fmt::Debug;
    use scoped_threadpool::Pool;

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
    fn test_unbounded() {
        let mut cache = LruCache::unbounded();
        for i in 0..13370 {
            cache.put(i, ());
        }
        assert_eq!(cache.len(), 13370);
    }

    #[test]
    fn test_with_hasher() {
        use crate::hasher_builder::HasherBuilder;

        let s = HasherBuilder::default();
        let mut cache = LruCache::with_hasher(16, s);

        for i in 0..13370 {
            cache.put(i, ());
        }
        assert_eq!(cache.len(), 16);
    }

    #[test]
    fn test_put_and_get() {
        let mut cache = LruCache::new(2);
        assert!(cache.is_empty());

        assert_eq!(cache.put("apple", "red"), None);
        assert_eq!(cache.put("banana", "yellow"), None);

        assert_eq!(cache.cap(), 2);
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

        assert_eq!(cache.cap(), 2);
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

        assert_eq!(cache.cap(), 2);
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

        assert_eq!(cache.put("apple", "red"), None);
        assert_eq!(cache.put("banana", "yellow"), None);
        assert_eq!(cache.put("pear", "green"), None);

        assert!(cache.get(&"apple").is_none());
        assert_opt_eq(cache.get(&"banana"), "yellow");
        assert_opt_eq(cache.get(&"pear"), "green");

        // Even though we inserted "apple" into the cache earlier it has since been removed from
        // the cache so there is no current value for `put` to return.
        assert_eq!(cache.put("apple", "green"), None);
        assert_eq!(cache.put("tomato", "red"), None);

        assert!(cache.get(&"pear").is_none());
        assert_opt_eq(cache.get(&"apple"), "green");
        assert_opt_eq(cache.get(&"tomato"), "red");
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
    fn test_peek_mut() {
        let mut cache = LruCache::new(2);

        cache.put("apple", "red");
        cache.put("banana", "yellow");

        assert_opt_eq_mut(cache.peek_mut(&"banana"), "yellow");
        assert_opt_eq_mut(cache.peek_mut(&"apple"), "red");
        assert!(cache.peek_mut(&"pear").is_none());

        cache.put("pear", "green");

        assert!(cache.peek_mut(&"apple").is_none());
        assert_opt_eq_mut(cache.peek_mut(&"banana"), "yellow");
        assert_opt_eq_mut(cache.peek_mut(&"pear"), "green");

        {
            let v = cache.peek_mut(&"banana").unwrap();
            *v = "green";
        }

        assert_opt_eq_mut(cache.peek_mut(&"banana"), "green");
    }

    #[test]
    fn test_peek_lru() {
        let mut cache = LruCache::new(2);

        assert!(cache.peek_lru().is_none());

        cache.put("apple", "red");
        cache.put("banana", "yellow");
        assert_opt_eq_tuple(cache.peek_lru(), ("apple", "red"));

        cache.get(&"apple");
        assert_opt_eq_tuple(cache.peek_lru(), ("banana", "yellow"));

        cache.clear();
        assert!(cache.peek_lru().is_none());
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
    fn test_pop_lru() {
        let mut cache = LruCache::new(200);

        for i in 0..75 {
            cache.put(i, "A");
        }
        for i in 0..75 {
            cache.put(i + 100, "B");
        }
        for i in 0..75 {
            cache.put(i + 200, "C");
        }
        assert_eq!(cache.len(), 200);

        for i in 0..75 {
            assert_opt_eq(cache.get(&(74 - i + 100)), "B");
        }
        assert_opt_eq(cache.get(&25), "A");

        for i in 26..75 {
            assert_eq!(cache.pop_lru(), Some((i, "A")));
        }
        for i in 0..75 {
            assert_eq!(cache.pop_lru(), Some((i + 200, "C")));
        }
        for i in 0..75 {
            assert_eq!(cache.pop_lru(), Some((74 - i + 100, "B")));
        }
        assert_eq!(cache.pop_lru(), Some((25, "A")));
        for _ in 0..50 {
            assert_eq!(cache.pop_lru(), None);
        }
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

    #[test]
    fn test_resize_larger() {
        let mut cache = LruCache::new(2);

        cache.put(1, "a");
        cache.put(2, "b");
        cache.resize(4);
        cache.put(3, "c");
        cache.put(4, "d");

        assert_eq!(cache.len(), 4);
        assert_eq!(cache.get(&1), Some(&"a"));
        assert_eq!(cache.get(&2), Some(&"b"));
        assert_eq!(cache.get(&3), Some(&"c"));
        assert_eq!(cache.get(&4), Some(&"d"));
    }

    #[test]
    fn test_resize_smaller() {
        let mut cache = LruCache::new(4);

        cache.put(1, "a");
        cache.put(2, "b");
        cache.put(3, "c");
        cache.put(4, "d");

        cache.resize(2);

        assert_eq!(cache.len(), 2);
        assert!(cache.get(&1).is_none());
        assert!(cache.get(&2).is_none());
        assert_eq!(cache.get(&3), Some(&"c"));
        assert_eq!(cache.get(&4), Some(&"d"));
    }

    #[test]
    fn test_send() {
        use std::thread;

        let mut cache = LruCache::new(4);
        cache.put(1, "a");

        let handle = thread::spawn(move || {
            assert_eq!(cache.get(&1), Some(&"a"));
        });

        assert!(handle.join().is_ok());
    }

    #[test]
    fn test_multiple_threads() {
        let mut pool = Pool::new(1);
        let mut cache = LruCache::new(4);
        cache.put(1, "a");

        let cache_ref = &cache;
        pool.scoped(|scoped| {
            scoped.execute(move || {
                assert_eq!(cache_ref.peek(&1), Some(&"a"));
            });
        });

        assert_eq!((cache_ref).peek(&1), Some(&"a"));
    }

    #[test]
    fn test_iter_forwards() {
        let mut cache = LruCache::new(3);
        cache.put("a", 1);
        cache.put("b", 2);
        cache.put("c", 3);

        {
            // iter const
            let mut iter = cache.iter();
            assert_eq!(iter.len(), 3);
            assert_opt_eq_tuple(iter.next(), ("c", 3));

            assert_eq!(iter.len(), 2);
            assert_opt_eq_tuple(iter.next(), ("b", 2));

            assert_eq!(iter.len(), 1);
            assert_opt_eq_tuple(iter.next(), ("a", 1));

            assert_eq!(iter.len(), 0);
            assert_eq!(iter.next(), None);
        }
        {
            // iter mut
            let mut iter = cache.iter_mut();
            assert_eq!(iter.len(), 3);
            assert_opt_eq_mut_tuple(iter.next(), ("c", 3));

            assert_eq!(iter.len(), 2);
            assert_opt_eq_mut_tuple(iter.next(), ("b", 2));

            assert_eq!(iter.len(), 1);
            assert_opt_eq_mut_tuple(iter.next(), ("a", 1));

            assert_eq!(iter.len(), 0);
            assert_eq!(iter.next(), None);
        }
    }

    #[test]
    fn test_iter_backwards() {
        let mut cache = LruCache::new(3);
        cache.put("a", 1);
        cache.put("b", 2);
        cache.put("c", 3);

        {
            // iter const
            let mut iter = cache.iter();
            assert_eq!(iter.len(), 3);
            assert_opt_eq_tuple(iter.next_back(), ("a", 1));

            assert_eq!(iter.len(), 2);
            assert_opt_eq_tuple(iter.next_back(), ("b", 2));

            assert_eq!(iter.len(), 1);
            assert_opt_eq_tuple(iter.next_back(), ("c", 3));

            assert_eq!(iter.len(), 0);
            assert_eq!(iter.next_back(), None);
        }

        {
            // iter mut
            let mut iter = cache.iter_mut();
            assert_eq!(iter.len(), 3);
            assert_opt_eq_mut_tuple(iter.next_back(), ("a", 1));

            assert_eq!(iter.len(), 2);
            assert_opt_eq_mut_tuple(iter.next_back(), ("b", 2));

            assert_eq!(iter.len(), 1);
            assert_opt_eq_mut_tuple(iter.next_back(), ("c", 3));

            assert_eq!(iter.len(), 0);
            assert_eq!(iter.next_back(), None);
        }
    }

    #[test]
    fn test_iter_forwards_and_backwards() {
        let mut cache = LruCache::new(3);
        cache.put("a", 1);
        cache.put("b", 2);
        cache.put("c", 3);

        {
            // iter const
            let mut iter = cache.iter();
            assert_eq!(iter.len(), 3);
            assert_opt_eq_tuple(iter.next(), ("c", 3));

            assert_eq!(iter.len(), 2);
            assert_opt_eq_tuple(iter.next_back(), ("a", 1));

            assert_eq!(iter.len(), 1);
            assert_opt_eq_tuple(iter.next(), ("b", 2));

            assert_eq!(iter.len(), 0);
            assert_eq!(iter.next_back(), None);
        }
        {
            // iter mut
            let mut iter = cache.iter_mut();
            assert_eq!(iter.len(), 3);
            assert_opt_eq_mut_tuple(iter.next(), ("c", 3));

            assert_eq!(iter.len(), 2);
            assert_opt_eq_mut_tuple(iter.next_back(), ("a", 1));

            assert_eq!(iter.len(), 1);
            assert_opt_eq_mut_tuple(iter.next(), ("b", 2));

            assert_eq!(iter.len(), 0);
            assert_eq!(iter.next_back(), None);
        }
    }

    #[test]
    fn test_iter_multiple_threads() {
        let mut pool = Pool::new(1);
        let mut cache = LruCache::new(3);
        cache.put("a", 1);
        cache.put("b", 2);
        cache.put("c", 3);

        let mut iter = cache.iter();
        assert_eq!(iter.len(), 3);
        assert_opt_eq_tuple(iter.next(), ("c", 3));

        {
            let iter_ref = &mut iter;
            pool.scoped(|scoped| {
                scoped.execute(move || {
                    assert_eq!(iter_ref.len(), 2);
                    assert_opt_eq_tuple(iter_ref.next(), ("b", 2));
                });
            });
        }

        assert_eq!(iter.len(), 1);
        assert_opt_eq_tuple(iter.next(), ("a", 1));

        assert_eq!(iter.len(), 0);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_iter_clone() {
        let mut cache = LruCache::new(3);
        cache.put("a", 1);
        cache.put("b", 2);

        let mut iter = cache.iter();
        let mut iter_clone = iter.clone();

        assert_eq!(iter.len(), 2);
        assert_opt_eq_tuple(iter.next(), ("b", 2));
        assert_eq!(iter_clone.len(), 2);
        assert_opt_eq_tuple(iter_clone.next(), ("b", 2));

        assert_eq!(iter.len(), 1);
        assert_opt_eq_tuple(iter.next(), ("a", 1));
        assert_eq!(iter_clone.len(), 1);
        assert_opt_eq_tuple(iter_clone.next(), ("a", 1));

        assert_eq!(iter.len(), 0);
        assert_eq!(iter.next(), None);
        assert_eq!(iter_clone.len(), 0);
        assert_eq!(iter_clone.next(), None);
    }

    #[test]
    fn test_that_pop_actually_detaches_node() {
        let mut cache = LruCache::new(5);

        cache.put("a", 1);
        cache.put("b", 2);
        cache.put("c", 3);
        cache.put("d", 4);
        cache.put("e", 5);

        assert_eq!(cache.pop(&"c"), Some(3));

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
    fn test_get_with_borrow() {
        use alloc::string::String;

        let mut cache = LruCache::new(2);

        let key = String::from("apple");
        cache.put(key, "red");

        assert_opt_eq(cache.get("apple"), "red");
    }

    #[test]
    fn test_get_mut_with_borrow() {
        use alloc::string::String;

        let mut cache = LruCache::new(2);

        let key = String::from("apple");
        cache.put(key, "red");

        assert_opt_eq_mut(cache.get_mut("apple"), "red");
    }
}
