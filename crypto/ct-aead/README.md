ct-aead
========

This crate contains a trait extending the suite of Aead traits offered by
https://github.com/RustCrypto/traits

This is needed to offer a decrypt interface with an additional constant-time property:
Timings, code paths, and data paths are the same whether or not the mac check succeeds.

It also implements this trait on the AesGcm AEAD's from the aes-gcm crate.
