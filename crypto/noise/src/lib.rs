// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A type-parameterized implementation of the Noise framework, with some
//! hooks for supporting MobileCoin's usage while talking to an enclave.

#![no_std]

extern crate alloc;

mod cipher_state;
mod handshake_hash;
mod handshake_state;
mod patterns;
mod protocol_name;
mod symmetric_state;

pub use crate::{
    cipher_state::{CipherError, CipherState, NoiseCipher},
    handshake_state::{HandshakeError, HandshakeOutput, HandshakeState, HandshakeStatus},
    patterns::{HandshakeIX, HandshakeNX, HandshakePattern},
    protocol_name::{ProtocolName, ProtocolNameError},
    symmetric_state::SymmetricOutput,
};
