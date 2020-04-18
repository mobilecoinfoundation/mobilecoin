mc-util-uri
=====

Portable code for handling URI's used in our system.

This crate is expected to be consumed by servers, test clients, and libmobilecoin.
It is not expected to be `no_std` crate because it relies on the rust `url` crate.
