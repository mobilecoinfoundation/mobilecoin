// Copyright (c) 2018-2022 The MobileCoin Foundation

//! This module contains objects and methods for communicating with the
//! Remote Attestation Services.

extern crate alloc;
extern crate core;

mod traits;

pub use crate::traits::{Error, RaClient, Result};
mod sim;
pub type Client = crate::sim::SimClient;

