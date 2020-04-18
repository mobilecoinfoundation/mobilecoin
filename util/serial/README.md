mc-util-serial
========

One way to easily pass Rust data structures to and from the Enclave is to use a
serialization library.

It doesn't particularly matter much which one we pick, and we have changed it
several times in the course of development. It is important that the same one
is used everywhere.

The goal of this crate is to provide a single common interface to whatever
third-party serialization library we choose, so that we can easily change it
later.

Please call into this crate rather than talking to bincode etc. directly, for
data that is being passed to / from the enclave
