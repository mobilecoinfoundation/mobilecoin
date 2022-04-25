// Copyright (c) 2018-2021 The MobileCoin Foundation

#![doc = include_str!("../README.md")]

mod cargo_build;
mod env;
mod utils;
mod vars;

pub use crate::{
    cargo_build::CargoBuilder,
    env::{Endianness, EndiannessError, Environment, EnvironmentError},
    utils::rerun_if_path_changed,
};
