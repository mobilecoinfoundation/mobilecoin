// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Interfaces for signing transactions

mod no_keys_ring_signer;
pub use no_keys_ring_signer::NoKeysRingSigner;

mod local_signer;
pub use local_signer::LocalRingSigner;

mod traits;
pub use traits::{Error, InputSecret, OneTimeKeyDeriveData, RingSigner, SignableInputRing};
