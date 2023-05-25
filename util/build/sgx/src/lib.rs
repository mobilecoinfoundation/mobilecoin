// Copyright (c) 2018-2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod config;
mod edger8r;
mod env;
mod libraries;
mod sign;
mod utils;

pub use crate::{
    config::{ConfigBuilder, TcsPolicy},
    edger8r::{Edger8r, Error as Edger8rError},
    env::{Error as EnvironmentError, IasMode, SgxEnvironment, SgxMode},
    libraries::SgxLibraryCollection,
    sign::SgxSign,
};
