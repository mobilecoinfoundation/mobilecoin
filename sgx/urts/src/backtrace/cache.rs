// Copyright (c) 2018-2020 MobileCoin Inc.

/// This module implements a generic cache structure using HashMap and
/// Box<Fn...
/// You can use Mutex<Cache<...>> to simplify some programming patterns.
use std::cmp::Eq;
use std::{
    boxed::Box,
    collections::hash_map::{Entry, HashMap},
    hash::Hash,
};

pub struct Cache<K: Eq + Hash, V> {
    map: HashMap<K, V>,
    fcn: Box<dyn FnMut(&K) -> V + Send>,
}

impl<K: Eq + Hash, V: Send> Cache<K, V> {
    pub fn new(callback: Box<dyn FnMut(&K) -> V + Send>) -> Self {
        Cache {
            map: HashMap::new(),
            fcn: callback,
        }
    }

    pub fn get(&mut self, key: K) -> &mut V {
        match self.map.entry(key) {
            Entry::Occupied(ent) => ent.into_mut(),
            Entry::Vacant(ent) => {
                let result = (self.fcn)(ent.key());
                ent.insert(result)
            }
        }
    }
}
