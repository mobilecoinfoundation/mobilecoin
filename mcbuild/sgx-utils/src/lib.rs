// Copyright (c) 2018-2020 MobileCoin Inc.

#![feature(external_doc)]
#![doc(include = "../README.md")]

mod config;
mod edger8r;
mod env;
mod sign;
mod vars;

pub use crate::{
    config::{ConfigBuilder, TcsPolicy},
    edger8r::Edger8r,
    env::{IasMode, SgxEnvironment, SgxEnvironmentError, SgxMode},
    sign::SgxSign,
};
