// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Meta-package to select dalek features without replicating selection logic
//! -everywhere-

#![no_std]

/// Re-export of curve25519_dalek
pub use curve25519_dalek as curve25519;

/// Re-export of ed25519_dalek
pub use ed25519_dalek as ed25519;

/// Re-export of x25519_dalek
pub use x25519_dalek as x25519;
