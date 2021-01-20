# X509 Utilities

This crate provides convenience methods for parsing, handling, and validating X509 certificate chains based on the [`x509-parser`](https://docs.rs/x509-parser) crate and, by extension, [*ring*](https://docs.rs/ring). It also includes necessary monkey-patching to support extracting (public) keys used by the `mc-crypto-keys` crate. from [`X509Certificate`](::x509_parser::certificate::X509Certificate) objects.

This crate should not be considered viable for use in an enclave at this time.
