// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{Error, KexRngPubkey, StoredRng};
use blake2::digest::generic_array::{ArrayLength, GenericArray};
use core::{convert::TryFrom, marker::Sized};
use mc_crypto_keys::Kex;
use mc_util_repr_bytes::ReprBytes;
use rand_core::{CryptoRng, RngCore};

/// Trait representing an object that can be created from a key exchange
/// message, which might also contain versioning info.
/// All KexRng and KexRngCore structs implement this.
pub trait NewFromKex<KexAlgo: Kex>: Sized {
    /// Create self by ephemeral-static key exchange, using a new random private
    /// key
    fn new_from_ephemeral_static<T: RngCore + CryptoRng>(
        rng: &mut T,
        pubkey: &KexAlgo::Public,
    ) -> (KexRngPubkey, Self);

    /// Create self by static-static key exchange
    fn new_from_static_static(
        our_private: &KexAlgo::Private,
        pubkey: &KexAlgo::Public,
    ) -> (KexRngPubkey, Self);

    /// Try to create self by key exchange against the ephemeral nonce and the
    /// static private key Might fail due to versioning or parsing mismatch
    fn try_from_kex_pubkey(
        pubkey: &KexRngPubkey,
        private_key: &KexAlgo::Private,
    ) -> Result<Self, Error>;
}

/// Trait representing a KexRngCore.
///
/// A KexRngCore is defined by providing a PRF (pseudorandom function)
/// The PRF takes as input a KexAlgo shared-secret and a counter value,
/// and produces a fixed number of bytes as output.
///
/// For a discussion of plausible implementations, see README
///
/// Implementation must provide an Output size in bytes as a compile-time
/// constant, and a VERSION_ID number, which should be unique across this crate.
pub trait KexRngCore<KexAlgo: Kex> {
    /// The number of bytes in an output
    type OutputSize: ArrayLength<u8>;

    /// The VERSION_ID used by this KexRngCore.
    /// These must be distinct per implementation that is incorporated into
    /// VersionedKexRng, or a compilation failure will follow.
    const VERSION_ID: u32;

    /// Given a secret curve point, and counter, produce output bytes
    ///
    /// For a random key, the consecutive outputs of this prf should be
    /// pseudorandom.
    fn prf(
        secret: &GenericArray<u8, <KexAlgo::Public as ReprBytes>::Size>,
        counter: &u64,
    ) -> GenericArray<u8, Self::OutputSize>;
}

/// Trait representing a type-erased KexRngCore with attached counter and buffer
/// It may support one or several versions, but must have a notion of a version
/// tag. The multiple versions might have different state or output sizes.
/// This is ultimately implemented by both the buffered wrapper of KexRngCore,
/// and the Versioned object that the clients use.
pub trait BufferedRng: Clone + Into<StoredRng> + TryFrom<StoredRng> {
    /// The current index of the RNG in its sequence.
    fn index(&self) -> u64;
    /// Observe the index'th output of the RNG
    fn peek(&self) -> &[u8];
    /// Increment the index compute the next value
    fn advance(&mut self);
    /// Return the version_id number
    fn version_id(&self) -> u32;
}

/// Trait representing a buffered Rng initializable by key exchange
/// We cannot hope to derive NewFromKex here, because versioning strategy is
/// involved, and the VersionedKexRng could dynamically have different versions.
pub trait KexRng<KexAlgo: Kex>: BufferedRng + NewFromKex<KexAlgo> {}
