// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Object representing trusted storage for tx out records.
//! Mediates between the bytes used in ORAM and the protobuf format,
//! the various ORAM vs. fog api error codes, etc.

use alloc::vec;

use aligned_cmov::{
    subtle::{Choice, ConstantTimeEq},
    typenum::{Unsigned, U1024, U16, U240, U4096, U64},
    A8Bytes, CMov,
};
use alloc::boxed::Box;
use mc_common::logger::Logger;
use mc_crypto_rand::McRng;
use mc_fog_types::view::{TxOutSearchResult, TxOutSearchResultCode};
use mc_fog_view_enclave_api::AddRecordsError;
use mc_oblivious_map::CuckooHashTableCreator;
use mc_oblivious_ram::PathORAM4096Z4Creator;
use mc_oblivious_traits::{
    OMapCreator, ORAMStorageCreator, ObliviousHashMap, OMAP_FOUND, OMAP_INVALID_KEY,
    OMAP_NOT_FOUND, OMAP_OVERFLOW,
};

// internal constants
// KeySize and ValueSize reflect the needs of e_tx_out_store
// We must choose an oblivious map algorithm that can support that
type KeySize = U16;
type ValueSize = U240;
// BlockSize is a tuning parameter for OMap which must become the ValueSize of
// the selected ORAM
type BlockSize = U1024;

// This selects an oblivious ram algorithm which can support queries of size
// BlockSize The ORAMStorageCreator type is a generic parameter to ETxOutStore
type ObliviousRAMAlgo<OSC> = PathORAM4096Z4Creator<McRng, OSC>;

// These are the requirements on the storage, this is imposed by the choice of
// oram algorithm
pub type StorageDataSize = U4096;
pub type StorageMetaSize = U64;

// This selects the stash size we will construct the oram with
const STASH_SIZE: usize = 32;

// This selects the oblivious map algorithm
type ObliviousMapCreator<OSC> = CuckooHashTableCreator<BlockSize, McRng, ObliviousRAMAlgo<OSC>>;

/// Object which holds ORAM and services TxOutRecord requests
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
pub struct ETxOutStore<OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>> {
    /// Oblivious map to hold ETxOutRecords
    omap: Box<<ObliviousMapCreator<OSC> as OMapCreator<KeySize, ValueSize, McRng>>::Output>,

    /// The size byte from the payload for the last ciphertext we stored in omap
    last_ciphertext_size_byte: u8,

    /// The logger object
    #[allow(unused)]
    logger: Logger,
}

impl<OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>> ETxOutStore<OSC> {
    pub fn new(desired_capacity: u64, logger: Logger) -> Self {
        Self {
            omap: Box::new(<ObliviousMapCreator<OSC> as OMapCreator<
                KeySize,
                ValueSize,
                McRng,
            >>::create(
                desired_capacity, STASH_SIZE, McRng::default
            )),
            last_ciphertext_size_byte: 0,
            logger,
        }
    }

    pub fn add_record(
        &mut self,
        search_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<(), AddRecordsError> {
        if search_key.len() != KeySize::USIZE {
            return Err(AddRecordsError::KeyWrongSize);
        }
        if ciphertext.len() > ValueSize::USIZE - 1 {
            return Err(AddRecordsError::ValueTooLarge);
        }
        if ciphertext.len() < ValueSize::USIZE.saturating_sub(256) {
            return Err(AddRecordsError::ValueWrongSize);
        }

        let mut key = A8Bytes::<KeySize>::default();
        let mut value = A8Bytes::<ValueSize>::default();

        key.clone_from_slice(search_key);
        value[0] = (ValueSize::USIZE - 1 - ciphertext.len()) as u8;
        let data_end = ValueSize::USIZE - value[0] as usize;
        (&mut value[1..data_end]).clone_from_slice(ciphertext);
        self.last_ciphertext_size_byte = value[0];

        // Note: Passing true means we allow overwrite, which seems fine since
        // the value is not changing
        let omap_result_code = self.omap.vartime_write(&key, &value, Choice::from(1));
        if omap_result_code == OMAP_INVALID_KEY {
            return Err(AddRecordsError::KeyRejected);
        } else if omap_result_code == OMAP_OVERFLOW {
            return Err(AddRecordsError::MapOverflow(
                self.omap.len(),
                self.omap.capacity(),
            ));
        } else if omap_result_code == OMAP_FOUND {
            // log::debug!(
            //    self.logger,
            //    "An omap key was added twice, overwriting previous value"
            // );
        } else if omap_result_code != OMAP_NOT_FOUND {
            panic!(
                "omap_result_code had an unexpected value: {}",
                omap_result_code
            );
        }
        Ok(())
    }

    pub fn find_record(&mut self, search_key: &[u8]) -> TxOutSearchResult {
        let mut result = TxOutSearchResult {
            search_key: search_key.to_vec(),
            result_code: TxOutSearchResultCode::InternalError as u32,
            ciphertext: vec![0u8; ValueSize::USIZE - 1 - self.last_ciphertext_size_byte as usize],
        };

        // Early return for bad search key
        if search_key.len() != KeySize::USIZE {
            result.result_code = TxOutSearchResultCode::BadSearchKey as u32;
            return result;
        }

        let mut key = A8Bytes::<KeySize>::default();
        key.clone_from_slice(search_key);

        let mut value = A8Bytes::<ValueSize>::default();
        value[0] = self.last_ciphertext_size_byte;

        // Do ORAM read operation and branchlessly handle the result code
        // OMAP_FOUND -> TxResultCode::Found
        // OMAP_NOT_FOUND -> TxResultCode::NotFound
        // OMAP_INVALID_KEY -> TxResultCode::BadSearchKey
        // Other -> TxResultCode::InternalError, debug_assert!(false)
        {
            let oram_result_code = self.omap.read(&key, &mut value);
            result.result_code.cmov(
                oram_result_code.ct_eq(&OMAP_FOUND),
                &(TxOutSearchResultCode::Found as u32),
            );
            result.result_code.cmov(
                oram_result_code.ct_eq(&OMAP_NOT_FOUND),
                &(TxOutSearchResultCode::NotFound as u32),
            );
            result.result_code.cmov(
                oram_result_code.ct_eq(&OMAP_INVALID_KEY),
                &(TxOutSearchResultCode::BadSearchKey as u32),
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

        // Copy the data in value[1..] to result.ciphertext, resizing if needed
        result
            .ciphertext
            .resize(ValueSize::USIZE - 1 - value[0] as usize, 0u8);
        let data_end = ValueSize::USIZE - value[0] as usize;
        result.ciphertext.copy_from_slice(&value[1..data_end]);

        result
    }
}
