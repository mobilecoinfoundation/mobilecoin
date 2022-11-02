mc-util-vec-map
===============

This is a map (container of key-value pairs) whose storage is arranged as two
`Heapless::Vec` objects, one for keys and one for values.

The motivation is somewhat connected to crates.io crates:
* https://docs.rs/vec_map/latest/vec_map/struct.VecMap.html
* https://docs.rs/vec-collections/latest/vec_collections/

However these crates use `std::vec::Vec` rather than a `no_std` friendly object.

We are using `heapless` because we want this to be friendly for hardware wallets.

This will be much smaller on the stack than some kind of hash table.
