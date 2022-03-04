// Copyright (c) 2018-2022 The MobileCoin Foundation

#![feature(min_type_alias_impl_trait)]

mod source;

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

pub use self::source::GrpcBlockSource;
