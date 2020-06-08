use alloc::{collections::VecDeque, vec::Vec};

struct Entry<K, V> {
    val: Option<(K, V)>,
    /// Index of the previous entry. If this entry is the head, ignore this field.
    prev: usize,
    /// Index of the next entry. If this entry is the tail, ignore this field.
    next: usize,
}

pub struct LruCache<K, V> {
    entries: Vec<Entry<K, V>>,
    free_indexes: VecDequeue<usize>,
    head: usize,
    tail: usize,
}

impl<K: PartialEq, V> LruCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        let mut free_indexes = VecDeque::with_capacity(capacity);
        for i in 0..capacity {
            free_indexes.push_back(i);
        }

        Self {
            entries: Vec::with_capacity(capacity),
            free_indexes,
            head: 0,
            tail: 0,
        }
    }

    /// Returns the number of elements in the cache.
    pub fn len(&self) -> usize {
        self.entries.capacity() - self.free_indexes.len()
    }

    /// Returns a bool indicating whether the cache is empty or not.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Checks if a given key is already in the cache, without touching it.
    pub fn contains(&self, key: &K) -> bool {
        self.iter().find(|(key2, _val)| key == *key2).is_some()
    }

    /// Insert a given key in the cache.
    ///
    /// This item becomes the front (most-recently-used) item in the cache.  If the cache is full,
    /// the back (least-recently-used) item will be removed.
    pub fn put(&mut self, key: K, val: V) -> bool {
        if let Some(v) = self.get_mut(&key) {
            *v = val;
            return false;
        }

        let entry = Entry {
            val: Some((key, val)),
            prev: 0,
            next: 0,
        };

        // If the cache is full, replace the oldest entry. Otherwise, add an entry.
        let new_head = if self.entries.len() == self.entries.capacity() {
            let i = self.pop_back();
            let _ = self.entries[i].val.take();
            self.entries[i] = entry;
            i
        } else {
            self.entries.push(entry);
            self.entries.len() - 1
        };

        self.push_front(new_head);

        true
    }

    /// Returns a reference to the value of the key in the cache or `None` if it
    /// is not present in the cache. Moves the key to the head of the LRU list if it exists.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        self.get_mut(key).map(|x| &*x)
    }

    /// Returns a mutable reference to the value of the key in the cache or `None` if it
    /// is not present in the cache. Moves the key to the head of the LRU list if it exists.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        match self.iter_mut().find(|(_index, key2, _val)| key == *key2) {
            Some((i, _key, _val)) => {
                self.touch(i);
                self.front_mut()
            }
            None => None,
        }
    }

    /// TODO
    pub fn pop(&mut self, key: &K) -> Option<V> {
        match self.iter_mut().find(|(_index, key2, _val)| key == *key2) {
            Some((i, _key, _val)) => {
                let v = self.entries[i].val.take();
                //self.remove(i);
                v.map(|e| e.1)
            }
            None => None,
        }
    }

    /// Returns a mutable reference to the front entry in the list (most recently used).
    pub fn front_mut(&mut self) -> Option<&mut V> {
        match self.entries.get_mut(self.head as usize).map(|e| &mut e.val) {
            Some(Some((_k, v))) => Some(v),
            _ => None,
        }
    }

    /// Iterate over the contents of this cache.
    pub fn iter(&self) -> LruCacheIterator<K, V> {
        LruCacheIterator {
            pos: self.head,
            done: self.entries.is_empty(),
            cache: self,
        }
    }

    /// Iterate mutably over the contents of this cache.
    fn iter_mut(&mut self) -> LruCacheMutIterator<K, V> {
        LruCacheMutIterator {
            pos: self.head,
            done: self.entries.is_empty(),
            cache: self,
        }
    }

    /// Touch a given entry, putting it first in the list.
    fn touch(&mut self, idx: usize) {
        if idx != self.head {
            self.remove(idx);
            self.push_front(idx);
        }
    }

    /// Remove an entry from the linked list.
    ///
    /// Note: This only unlinks the entry from the list; it does not remove it from the array.
    fn remove(&mut self, i: usize) {
        let prev = self.entries[i].prev;
        let next = self.entries[i].next;

        if i == self.head {
            self.head = next;
        } else {
            self.entries[prev].next = next;
        }

        if i == self.tail {
            self.tail = prev;
        } else {
            self.entries[next].prev = prev;
        }
    }

    /// Insert a new entry at the head of the list.
    fn push_front(&mut self, i: usize) {
        if self.entries.len() == 1 {
            self.tail = i;
        } else {
            self.entries[i].next = self.head;
            self.entries[self.head].prev = i;
        }
        self.head = i;
    }

    /// Remove the last entry from the linked list. Returns the index of the removed entry.
    ///
    /// Note: This only unlinks the entry from the list; it does not remove it from the array.
    fn pop_back(&mut self) -> usize {
        let old_tail = self.tail;
        let new_tail = self.entries[old_tail].prev;
        self.tail = new_tail;
        old_tail
    }
}

/// Iterator over values in an LruCache, from most-recently-used to least-recently-used.
pub struct LruCacheIterator<'a, K: 'a, V: 'a> {
    cache: &'a LruCache<K, V>,
    pos: usize,
    done: bool,
}

impl<'a, K, V> Iterator for LruCacheIterator<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }

            // Use a raw pointer because the compiler doesn't know that subsequent calls can't alias.
            let entry = unsafe { &*(&self.cache.entries[self.pos] as *const Entry<K, V>) };

            if self.pos == self.cache.tail {
                self.done = true;
            }
            self.pos = entry.next;

            if let Some((ref k, ref v)) = entry.val {
                return Some((k, v));
            }
        }
    }
}

/// Mutable iterator over values in an LruCache, from most-recently-used to least-recently-used.
struct LruCacheMutIterator<'a, K: 'a, V: 'a> {
    cache: &'a mut LruCache<K, V>,
    pos: usize,
    done: bool,
}

impl<'a, K, V> Iterator for LruCacheMutIterator<'a, K, V> {
    type Item = (usize, &'a K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }

            // Use a raw pointer because the compiler doesn't know that subsequent calls can't alias.
            let entry = unsafe { &mut *(&mut self.cache.entries[self.pos] as *mut Entry<K, V>) };

            let index = self.pos;
            if self.pos == self.cache.tail {
                self.done = true;
            }
            self.pos = entry.next;

            if let Some((ref k, ref mut v)) = entry.val {
                return Some((index, k, v));
            }
        }
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn test_put_and_get() {
        let mut cache = LruCache::new(2);
        assert!(cache.is_empty());

        assert_eq!(cache.put("apple", "red"), true);
        assert_eq!(cache.put("banana", "yellow"), true);

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

        assert_eq!(cache.put("apple", "red"), true);
        assert_eq!(cache.put("apple", "green"), false);

        assert_eq!(cache.len(), 1);
        assert_opt_eq(cache.get(&"apple"), "green");
    }

    #[test]
    fn test_put_removes_oldest() {
        let mut cache = LruCache::new(2);

        assert_eq!(cache.put("apple", "red"), true);
        assert_eq!(cache.put("banana", "yellow"), true);
        assert_eq!(cache.put("pear", "green"), true);

        assert!(cache.get(&"apple").is_none());
        assert_opt_eq(cache.get(&"banana"), "yellow");
        assert_opt_eq(cache.get(&"pear"), "green");

        // Even though we inserted "apple" into the cache earlier it has since been removed from
        // the cache so there is no current value for `put` to return.
        assert_eq!(cache.put("apple", "green"), true);
        assert_eq!(cache.put("tomato", "red"), true);

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
        let mut cache = LruCache::new(3);
        cache.put("a", 1);
        cache.put("b", 2);
        cache.put("c", 3);

        let mut iter = cache.iter();
        assert_opt_eq_tuple(iter.next(), ("c", 3));

        assert_opt_eq_tuple(iter.next(), ("b", 2));

        assert_opt_eq_tuple(iter.next(), ("a", 1));

        assert_eq!(iter.next(), None);
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
}
