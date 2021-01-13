// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]
extern crate alloc;

// Only one of these is needed at a time but they are both portable
pub mod trusted;
pub mod untrusted;
