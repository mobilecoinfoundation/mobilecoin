// Copyright (c) 2018-2020 MobileCoin Inc.

#![no_std]
extern crate alloc;

// Only one of these is needed at a time but they are both portable
pub mod trusted;
pub mod untrusted;
