# X509 Test Utilities

This crate exists to provide a method to create "one-shot" certificate chains for use in unit test suites. At present, this is accomplished via shell calls to the `openssl` binary, which means it will need to be installed.

Making this use, e.g. `openssl-sys` is therefore an obvious TOOD.
