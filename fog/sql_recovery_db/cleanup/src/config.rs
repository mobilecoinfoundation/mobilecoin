// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Specifies configuration for the Fog SQL Recovery DB cleanup binary.

use clap::Parser;
use serde::Serialize;

/// Configuration parameters for the Fog SQL recovery DB cleanup task.
#[derive(Clone, Parser, Serialize)]
#[clap(version)]
pub struct SqlRecoveryDbCleanupConfig {
    /// If set to true, performs cleanup task for unused egress keys.
    #[clap(long)]
    pub egress_keys: bool,

    /// If set to true, prints out any DB entries that would be cleared by the
    /// command and doesn't execute the deletion.
    #[clap(long)]
    pub dry_run: bool,
}
