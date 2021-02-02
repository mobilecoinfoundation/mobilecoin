// Copyright (c) 2018-2021 MobileCoin Inc.

//! Fog Signature Scheme implementation

// 1. Sign a subjectPublicKeyInfo with a user's AccountKey
// 2. Sign a Report List structure with an Ed25519 keypair (loaded from privkey)
// 3. Verify the chain of trust from AccountKey -> CA -> (chain) -> Report List
//
// Out-of-scope: verifying a particular report in the list has required security properties

pub enum Error {}
