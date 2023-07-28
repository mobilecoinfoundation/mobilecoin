// Copyright (c) 2018-2022 The MobileCoin Foundation

//! An implementation of the IAS client for simulation purposes

use crate::traits::{RaClient, Result};
use mc_attest_core::{
    EpidGroupId, SigRL
};

#[derive(Clone)]
pub struct SimClient;

/// The mock remote attestation client implementation
impl RaClient for SimClient {
    fn new(_credentials: &str) -> Result<Self> {
        Ok(Self)
    }
    /// Return a default SigRL, regardless of the given EpidGroupId
    fn get_sigrl(&self, _gid: EpidGroupId) -> Result<SigRL> {
        Ok(SigRL::default())
    }
}
