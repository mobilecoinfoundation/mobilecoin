ocall-oram-storage
==================

The enclave has limited heap space. In Linux, it is permitted to have massive
heaps e.g. 40 GB, but this then relies on the linux paging mechanism.

An alternative to using a large heap is to pass encrypted memory out via OCALLs
and then request it again later. Untrusted can do whatever it wants to store and
retrieve these.

The `edl` crate provides the `.edl` file defining these calls.

The `trusted` crate provides an object implementing the `ORAMStorage` trait
via these OCALLs. Everything around authenticated encryption of the values that
leave and return happens here.

The `untrusted` crate provides untrusted-side implementations.
We provide one based on the rust global allocator.

Note:

For the trusted-side object, which is implementing `ORAMStorage` trait, we
have to think of the storage space as a tree. This is because the authentication
process takes advantage of the tree structure, and becomes simpler and faster
because we assume that whenever we load parts of the tree, we are loading an
entire root-to-leaf path. This is also needed because the trusted-side object
is responsible to implement treetop caching, so it needs to be aware of the
tree structure.

For the untrusted API, the storage is thought of as just dumb blocks, and we
are basically just doing mass storage. It's possible that it could be somehow
optimized in the future knowing that the queries are always corresponding to
tree paths, but code for that doesn't exist right now, and the API doesn't
reflect that promise. In the future we likely also want an extension where you
can load two different paths simultaneously. So we can work that out when we get there.
