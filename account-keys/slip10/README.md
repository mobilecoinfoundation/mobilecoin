# MobileCoin SLIP-0010-Based Key Derivation

This crate provides utilities to handle SLIP-0010 key bytes and their relation to the MobileCoin [`AccountKey`](mc_account_keys::AccountKey) structure, which contains a pair of Ristretto255 view/spend private scalars.

This also features a trait to create a Slip10Key from entropy and path, along with the canonical method of converting a BIP-39 [`Mnemonic`](tiny_bip32::Mnemonic) with a given BIP-32 path into a [`Slip10Key`](Slip10Key) usable within MobileCoin.
