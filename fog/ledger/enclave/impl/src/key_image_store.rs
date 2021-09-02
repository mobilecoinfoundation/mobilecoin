// Copyright (c) 2018-2021 The MobileCoin Foundation
//! Object representing trusted storage for key image records.
//! Mediates between the bytes used in ORAM and the protobuf format,
//! the various ORAM vs. fog api error codes, etc.
#![deny(missing_docs)]
use aligned_cmov::{
    subtle::{Choice, ConstantTimeEq},
    typenum::{U1024, U16, U32, U4096, U64},
    A8Bytes, CMov,
};
use alloc::boxed::Box;
use core::convert::TryInto;
use mc_common::logger::{log, Logger};
use mc_crypto_rand::McRng;
use mc_fog_ledger_enclave_api::AddRecordsError;
use mc_fog_types::ledger::{KeyImageResult, KeyImageResultCode};
use mc_oblivious_map::CuckooHashTableCreator;
use mc_oblivious_ram::PathORAM4096Z4Creator;
use mc_oblivious_traits::{
    OMapCreator, ORAMStorageCreator, ObliviousHashMap, OMAP_FOUND, OMAP_INVALID_KEY,
    OMAP_NOT_FOUND, OMAP_OVERFLOW,
};
use mc_transaction_core::ring_signature::KeyImage;
use mc_watcher_api::TimestampResultCode;

/// internal constants
/// KeySize and ValueSize reflect the needs of key_image_store
/// We must choose an oblivious map algorithm that can support that
type KeySize = U32;
type ValueSize = U16;
/// BlockSize is a tuning parameter for OMap which must become the ValueSize of
/// the selected ORAM
type BlockSize = U1024;
/// This selects an oblivious ram algorithm which can support queries of size
/// BlockSize The ORAMStorageCreator type is a generic parameter to
/// KeyImageStore
type ObliviousRAMAlgo<OSC> = PathORAM4096Z4Creator<McRng, OSC>;
/// These are the requirements on the storage, this is imposed by the choice of
/// oram algorithm
/// Storage Data Size U4096 for ORAM algorithm
pub type StorageDataSize = U4096;
/// Storage Meta Size U64 for ORAL algorithm
pub type StorageMetaSize = U64;

/// This selects the stash size we will construct the oram with
const STASH_SIZE: usize = 32;

/// This selects the oblivious map algorithm
type ObliviousMapCreator<OSC> = CuckooHashTableCreator<BlockSize, McRng, ObliviousRAMAlgo<OSC>>;

/// Object which holds ORAM and services KeyImageRecord requests
///
/// This object handles translations between protobuf types, and the aligned
/// chunks of bytes Key and Value used in the oblivious map interface.
///
/// - The size in the OMAP is ValueSize which must be divisible by 8,
/// - The user actually gives us a serialized protobuf
/// - We use a wire format in the omap where value[0] = ValueSize - 1 -
///   ciphertext.len(), ValueSize must be within 255 bytes of ciphertext.len().
/// - When the lookup misses, we try to obliviously return a buffer of the
///   normal size. We do this by remembering the ciphertext size byte of the
///   last stored ciphertext.
pub struct KeyImageStore<OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>> {
    /// Oblivious map to hold KeyImageStoreRecords
    omap: Box<<ObliviousMapCreator<OSC> as OMapCreator<KeySize, ValueSize, McRng>>::Output>,

    /// The logger object
    logger: Logger,
}

impl<OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>> KeyImageStore<OSC> {
    pub fn new(desired_capacity: u64, logger: Logger) -> Self {
        Self {
            omap: Box::new(<ObliviousMapCreator<OSC> as OMapCreator<
                KeySize,
                ValueSize,
                McRng,
            >>::create(
                desired_capacity, STASH_SIZE, McRng::default
            )),
            logger,
        }
    }

    /// add a key image containing block index and timestamp
    pub fn add_record(
        &mut self,
        key_image: &KeyImage,
        block_index: u64,
        timestamp: u64,
    ) -> Result<(), AddRecordsError> {
        let mut value = A8Bytes::<ValueSize>::default();
        let mut key = A8Bytes::<KeySize>::default(); // key used to add to the oram for key image
        key.clone_from_slice(&key_image.as_ref());
        // Flip the first byte of key image, when used as a key in the oblivious
        // map. This is because we will use key image as a key in the map,
        // but the map does not support all zeroes as a key. All zeroes is a
        // valid curve point. But if we flip the first byte, it turns out that
        // isn't a valid curve point, in the Ristretto group.
        // So this prevents the OMAP_INVALID_KEY error path.
        key[0] = !key[0];
        // write block index data to  value[0..8] write the time stamp data to
        // value[8..16]
        value[0..8].clone_from_slice(&block_index.to_le_bytes());
        value[8..16].clone_from_slice(&timestamp.to_le_bytes());
        // Note: Passing true means we allow overwrite, which seems fine since
        // the search_key value is not changing
        let omap_result_code = self.omap.vartime_write(&key, &value, Choice::from(1));
        if omap_result_code == OMAP_INVALID_KEY {
            return Err(AddRecordsError::KeyRejected);
        } else if omap_result_code == OMAP_OVERFLOW {
            return Err(AddRecordsError::MapOverflow(
                self.omap.len(),
                self.omap.capacity(),
            ));
        } else if omap_result_code == OMAP_FOUND {
            log::debug!(self.logger, "A key image record was clobbered");
        } else if omap_result_code != OMAP_NOT_FOUND {
            panic!(
                "omap_result_code had an unexpected value: {}",
                omap_result_code
            );
        }
        Ok(())
    }

    /// return new struct KeyImageResult which contains block index and
    /// timestamp of key image as ref to convert key image to 32 bits,
    /// call the oram to query to to key image data
    pub fn find_record(&mut self, key_image: &KeyImage) -> KeyImageResult {
        let mut result = KeyImageResult {
            key_image: *key_image,
            spent_at: u64::MAX,
            key_image_result_code: KeyImageResultCode::KeyImageError as u32,
            timestamp: u64::MAX,
            timestamp_result_code: TimestampResultCode::TimestampFound as u32,
        };

        let mut key = A8Bytes::<KeySize>::default(); // key used to query the oram for key image
        key.clone_from_slice(&key_image.as_ref());
        // Flip the first byte of key image, when used as a key in the oblivious
        // map. This is because we will use key image as a key in the map,
        // but the map does not support all zeroes as a key. All zeroes is a
        // valid curve point. But if we flip the first byte, it turns out that
        // isn't a valid curve point, in the Ristretto group.
        // So this prevents the OMAP_INVALID_KEY error path.
        key[0] = !key[0];

        // value used to save the reuslt of querying
        //the oram for key image value using key
        // we want for the spent time stamp to have u64 max if it is not found
        let mut value = A8Bytes::<ValueSize>::default();

        // set the bytes to all ones so  binary corresponds to u64::MAX because we want
        // value to be the same size irrespective if it is found or not
        // we want to return the same size back to the user so that no one can guess
        // based on the size what value is returned back to user
        for byte in value.iter_mut() {
            *byte = u8::MAX;
        }

        // Do ORAM read operation and branchlessly handle the result code
        // OMAP_FOUND -> KeyImageResultCode::Spent
        // OMAP_NOT_FOUND -> KeyImageResultCode::NotSpent
        // OMAP_INVALID_KEY -> KeyImageResultCode::KeyImageError
        // Other -> debug_assert!(false)
        {
            let oram_result_code = self.omap.read(&key, &mut value);
            result.key_image_result_code.cmov(
                oram_result_code.ct_eq(&OMAP_FOUND),
                &(KeyImageResultCode::Spent as u32),
            );
            result.key_image_result_code.cmov(
                oram_result_code.ct_eq(&OMAP_NOT_FOUND),
                &(KeyImageResultCode::NotSpent as u32),
            );
            result.key_image_result_code.cmov(
                oram_result_code.ct_eq(&OMAP_INVALID_KEY),
                &(KeyImageResultCode::KeyImageError as u32),
            );
            // This is debug assert to avoid creating a branch in production
            debug_assert!(
                oram_result_code == OMAP_FOUND
                    || oram_result_code == OMAP_NOT_FOUND
                    || oram_result_code == OMAP_INVALID_KEY,
                "oram_result_code had an unexpected value: {}",
                oram_result_code
            );
        }

        // Copy the data in value[0..8] to result.spent_at which represents the
        // block_index Copy the data in value[8..16] to result.timestamp
        result.spent_at = u64::from_le_bytes(value[0..8].try_into().unwrap());
        result.timestamp = u64::from_le_bytes(value[8..16].try_into().unwrap());

        result
    }
}
