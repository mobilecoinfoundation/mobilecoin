mc-fog-types
============

This crate provides prost versions of some types related to fog reports.

This is needed because some of these types are consumed by `fog-report-validation`
crate which is needed to build transaction. However, when we use the version of
these types crates using the `protobuf` crate, we end up with a dependency
on grpcio. However, this is not acceptable to android-bindings and libmobilecoin,
which do not want (and should not need) to compile grpcio for their targets.

This will also help with eventually making `fog-report-validation` eventually
`no_std` compatible, which is desirable for making embedded devices that can
construct mobilecoin transactions to fog recipients.
