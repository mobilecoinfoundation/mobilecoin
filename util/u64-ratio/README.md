mc-util-u64-ratio
=================

This crate provides a type `U64Ratio` which represents a ratio of two `u64`
integers, and supports some basic functionality using these:

* Comparing two ratios
* Multiplying a `u64` by the ratio, rounding up or down as the caller requests.

This does not use `float` or decimal or rational classes under the hood, it is
very simple and `no_std` compatible. This was created to support implementation
of partial fill rules from MCIP 42 in a more maintainable way.
