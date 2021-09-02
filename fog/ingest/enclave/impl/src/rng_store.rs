// Copyright (c) 2018-2021 The MobileCoin Foundation

use aligned_cmov::{
    typenum::{U1024, U16, U32, U4096, U64, U8},
    Aligned, GenericArray,
};
use alloc::boxed::Box;
use mc_common::logger::Logger;
use mc_crypto_rand::McRng;
use mc_fog_kex_rng::{KexRng20201124, KexRngCore};
use mc_oblivious_map::CuckooHashTableCreator;
use mc_oblivious_ram::PathORAM4096Z4Creator;
use mc_oblivious_traits::{
    OMapCreator, ORAMStorageCreator, ObliviousHashMap, OMAP_INVALID_KEY, OMAP_OVERFLOW,
};

// internal helpers
// KexRng algo that is used at this revision
type KexRngAlgo = KexRng20201124;

// KeySize and ValueSize reflect the needs of rng_store
// We must choose an oblivious map algorithm that can support that
type KeySize = U32;
type ValueSize = U8;
// BlockSize is a tuning parameter for OMap which must become the ValueSize of
// the selected ORAM
type BlockSize = U1024;
// This selects an oblivious ram algorithm which can support queries of size
// BlockSize The ORAMStorageCreator type is a generic parameter to RngStore
type ObliviousRAMAlgo<OSC> = PathORAM4096Z4Creator<McRng, OSC>;

// These are the requirements on the storage, this is imposed by the choice of
// oram algorithm

/// The storage data size which OSC must be able to support
pub type StorageDataSize = U4096;
/// The storage meta size which OSC must be able to support
pub type StorageMetaSize = U64;

// This is the stash size we will construct the ORAM with
// TODO: FOG-298 This should be a runtime configurable parameter with a
// build-time lower bound.
const STASH_SIZE: usize = 32;

// This selects the oblivious map algorithm
type ObliviousMapCreator<OSC> = CuckooHashTableCreator<BlockSize, McRng, ObliviousRAMAlgo<OSC>>;

/// Object which holds user -> rng map in ORAM
pub struct RngStore<OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>> {
    /// Oblivious map to hold view-pub-key -> KexRngCore mapping
    omap: Option<Box<<ObliviousMapCreator<OSC> as OMapCreator<KeySize, ValueSize, McRng>>::Output>>,
    /// Desired capacity for the oblivious map
    desired_capacity: u64,
    /// Logger object
    #[allow(unused)]
    logger: Logger,
}

impl<OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>> RngStore<OSC> {
    /// Make a new RngStore
    pub fn new(desired_capacity: u64, logger: Logger) -> Self {
        Self {
            omap: Some(Box::new(<ObliviousMapCreator<OSC> as OMapCreator<
                KeySize,
                ValueSize,
                McRng,
            >>::create(
                desired_capacity, STASH_SIZE, McRng::default
            ))),
            desired_capacity,
            logger,
        }
    }

    /// Get the real capacity of the underlying oram
    pub fn capacity(&self) -> u64 {
        self.omap.as_ref().map(|omap| omap.capacity()).unwrap_or(0)
    }

    /// Clear the RngStore, throwing out all existing Rngs.
    ///
    /// This must coincide with rotating the egress key and publishing
    /// a new KexRngPubkey.
    pub fn clear(&mut self) {
        // Force destruction of self.omap and release of its resources before recreating
        // it, otherwise we cannot assign more than 50% of memory resources to
        // it. TODO: It might be more efficient to add a clear function to
        // ObliviousMap object, so that we only clear memory instead of
        // deallocating and reallocating.
        self.omap = None;
        // Recreate the map, it will now be in the empty state.
        self.omap = Some(Box::new(<ObliviousMapCreator<OSC> as OMapCreator<
            KeySize,
            ValueSize,
            McRng,
        >>::create(
            self.desired_capacity,
            STASH_SIZE,
            McRng::default,
        )));
    }

    /// Get the KexRng algorithm version number used
    pub fn kex_rng_algo_version(&self) -> u32 {
        KexRngAlgo::VERSION_ID
    }

    /// Get the next rng output for a user, given their shared secret,
    /// produced from key exchange with the egress key.
    ///
    /// Arguments: shared_secret bytes, success_decrypting bytes.
    /// - shared_secret: Bytes of shared secret after key exchange with egress
    ///   key
    /// - success_decrypting: Indicates that this shared secret came from fake
    ///   data after we failed to decrypt a fog hint. In this case we don't want
    ///   to have side-effects on the counter table, so we don't increment the
    ///   counter value.
    ///
    /// Returns: (overflowed, fog_search_key bytes)
    ///
    /// overflowed is false if the operation completed successfully
    /// overflowed is true if the map has overflowed
    ///
    /// Note: This function is constant-time up until the first time the map
    /// overflows, but after the map has overflowed,
    /// the table must be cleared before this function is called again, or we
    /// risk generating duplicate fog_search_key bytes for a single user,
    /// which is a security problem.
    pub fn next_rng_output(&mut self, shared_secret: &[u8; 32]) -> (bool, GenericArray<u8, U16>) {
        // Get aligned shared_secret
        let mut aligned_shared_secret =
            Aligned(*GenericArray::<u8, U32>::from_slice(shared_secret));
        // Flip the first byte of shared secret, when used as a key in the oblivious
        // map. This is because we will use shared_secret as a key in the map,
        // but the map does not support all zeroes as a key. All zeroes is a
        // valid curve point. But if we flip the first byte, it turns out that
        // isn't a valid curve point, in the Ristretto group.
        // So this prevents the OMAP_INVALID_KEY error path.
        aligned_shared_secret[0] = !aligned_shared_secret[0];

        // Perform access_and_insert at this position
        // The all-zeroes buffer is used as the default value
        let mut output = GenericArray::<u8, U16>::default();
        let result_code = self.omap.as_mut().unwrap().access_and_insert(
            &aligned_shared_secret,
            &Default::default(),
            &mut McRng::default(),
            |_status_code, counter_buf| {
                let mut counter_val = u64::from_ne_bytes(*counter_buf.as_ref());
                // Compute the next rng output given shared secret and counter value
                output = KexRngAlgo::prf(GenericArray::from_slice(shared_secret), &counter_val);
                // Wrapping add is used to avoid creating a branch in the production asm.
                counter_val = counter_val.wrapping_add(1u64);
                *counter_buf = Aligned(GenericArray::from(counter_val.to_ne_bytes()));
            },
        );
        debug_assert!(result_code != OMAP_INVALID_KEY);
        (result_code == OMAP_OVERFLOW, output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{collections::BTreeSet, format};
    use core::convert::TryFrom;
    use mc_common::logger::test_with_logger;
    use mc_crypto_keys::RistrettoPublic;
    use mc_oblivious_traits::HeapORAMStorageCreator;

    // Test that all zeroes + first byte flipped is not a valid curve point
    #[test]
    fn test_expected_invalid_curve_point() {
        let mut shared_secret = [0u8; 32];
        shared_secret[0] = !shared_secret[0];
        assert!(RistrettoPublic::try_from(&shared_secret).is_err());
    }

    // Test that all zeroes shared secret works with rng store
    #[test_with_logger]
    fn test_all_zeroes_shared_secret(logger: Logger) {
        let mut rng_store = RngStore::<HeapORAMStorageCreator>::new(512, logger);

        let mut outputs = BTreeSet::default();

        for _ in 0..100 {
            let (overflow, rng_output) = rng_store.next_rng_output(&[0u8; 32]);
            assert!(!overflow, "rng store overflowed unexpectedly");
            let success = outputs.insert(rng_output);
            assert!(success, "output was not unique");
        }
    }
}
