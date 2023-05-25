fog_types
=========

Fog types is a `no_std` crate containing many grpc API types used in Fog.

These generally cannot be in the same crate as GRPC API's because grpc is not `no_std`.

These types may be consumed by both clients and fog enclaves, and encoded versions of them
may be written to fog databases.

In `fog/api` we test that these conform to protos.
