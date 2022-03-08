// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]
#![deny(missing_docs)]

//! ORAM storage is arranged as a complete balanced binary tree, with each node
//! holding a fixed-size block of size roughly a linux page. Each node also has
//! an associated fixed-size metadata block, about 100 times smaller.
//!
//! It is possible to store all of this on the heap inside of SGX, up to the
//! limits of the enclave heap size. There are also performance consequences of
//! exceeding the EPC size (enclave page cache).
//!
//! In ORAM implementations such as ZeroTrace, OCALL's are used to allow the
//! enclave to store this data outside of SGX. This data must be encrypted when
//! it leaves, and decrypted and authenticated when it returns. From trusted's
//! point of view, it doesn't matter much how untrusted chooses to actually
//! store the blocks, as long as it returns the correct ones -- if
//! authentication fails, the enclave is expected to panic.
//!
//! Tree-top caching means that the top of the tree is on the heap in SGX and
//! only the bottom part is across the OCALL boundary. This can result in
//! significant perf improvements especially when using a recursive ORAM
//! strategy.
//!
//! In this impementation, the tree-top caching size is configurable via a
//! global variable.
//!
//! For an overview and analysis of the authentication scheme implemented here,
//! the reader is directed to README.md for this crate.

extern crate alloc;

use alloc::vec;

use aes::{
    cipher::{generic_array::GenericArray as CipherGenericArray, NewCipher, StreamCipher},
    Aes256Ctr,
};
use aligned_cmov::{typenum, A64Bytes, A8Bytes, ArrayLength, GenericArray};
use alloc::vec::Vec;
use balanced_tree_index::TreeIndex;
use core::{
    cmp::max,
    ops::Add,
    sync::atomic::{AtomicU32, Ordering},
};
use displaydoc::Display;
use lazy_static::lazy_static;
use mc_oblivious_traits::{HeapORAMStorage, ORAMStorage, ORAMStorageCreator};
use mc_sgx_compat::sync::Mutex;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use typenum::{PartialDiv, PowerOfTwo, Sum, Unsigned, U8};

mod extra_meta;
use extra_meta::{compute_block_hash, ExtraMeta, ExtraMetaSize, Hash};

lazy_static! {
    /// The tree-top caching threshold, specified as log2 of a number of bytes.
    ///
    /// This is the approximate number of bytes that can be stored on the heap in the enclave
    /// for a single ORAM storage object.
    ///
    /// This is expected to be tuned as a function of
    /// (1) number of (recursive) ORAM's needed
    /// (2) enclave heap size, set at build time
    ///
    /// Changing this number influences any ORAM storage objects created after the change,
    /// but not before. So, it should normally be changed during enclave init, if at all.
    pub static ref TREETOP_CACHING_THRESHOLD_LOG2 : AtomicU32 = AtomicU32::new(25u32); // 32 MB

    // An extra mutex which we lock across our OCALLs, this is done to detect if the untrusted
    // attacker does strange things.
    //
    // The purpose of this mutex is to try to guard against re-entrancy into the enclave.
    // Re-entrancy could occur if the untrusted side handles the OCALL by turning around and
    // making more ECALLs, never returning from first OCALL and setting up unexpected state in enclave.
    // Another worrisome scenario is, they could never return from first OCALL and let other threads
    // continue to proceed and evenutally make more OCALLs.
    // Then the first OCALL could be responded to adaptively etc. in a way that the enclave designer
    // might not expect. Using a mutex to serialize the OCALLs would prevent that.
    //
    // Yogseh Swami "Intel SGX Remote Attestation is not sufficient" discusses such issues in detail:
    // https://www.blackhat.com/docs/us-17/thursday/us-17-Swami-SGX-Remote-Attestation-Is-Not-Sufficient-wp.pdf
    //
    // It is not clear that this is actually needed to prevent problems,
    // we just haven't done a detailed anaysis.
    //
    // If you do such an analysis and conclude it's safe, you could remove this and leave a code comment.
    // However, the cost of this is likely very low since the mutex is uncontended -- our real enclaves
    // only have one OMAP object, and its API is &mut, so the caller must wrap it in a mutex anyways,
    // and this is unlikely to change anytime soon. (Maybe we will have parallel ORAM someday???)
    static ref OCALL_REENTRANCY_MUTEX: Mutex<()> = Mutex::new(());
}

/// Cipher type. Anything implementing StreamCipher and NewCipher at 128
/// bit security should be acceptable
type CipherType = Aes256Ctr;
/// Parameters of the cipher as typedefs (which eases syntax)
type NonceSize = <CipherType as NewCipher>::NonceSize;
type KeySize = <CipherType as NewCipher>::KeySize;

// Make an aes nonce per the docu
fn make_aes_nonce(block_idx: u64, block_ctr: u64) -> CipherGenericArray<u8, NonceSize> {
    let mut result = GenericArray::<u8, NonceSize>::default();
    result[0..8].copy_from_slice(&block_idx.to_le_bytes());
    result[8..16].copy_from_slice(&block_ctr.to_le_bytes());
    result
}

/// An ORAMStorage type which stores data with untrusted storage, over an OCALL.
/// This must encrypt the data which is stored, and authenticate the data when
/// it returns.
pub struct OcallORAMStorage<DataSize, MetaSize>
where
    DataSize: ArrayLength<u8> + PowerOfTwo + PartialDiv<U8>,
    MetaSize: ArrayLength<u8> + Add<ExtraMetaSize>,
    Sum<MetaSize, ExtraMetaSize>: ArrayLength<u8> + PartialDiv<U8>,
{
    // The id returned from untrusted for the untrusted-side storage if any, or 0 if none.
    allocation_id: u64,
    // The size of the binary tree the caller asked us to provide storage for, must be a power of
    // two
    count: u64,
    // The maximum count for the treetop storage,
    // based on what we loaded from TREETOP_CACHING_THRESHOLD_LOG2 at construction time
    // This must never change after construction.
    treetop_max_count: u64,
    // The storage on the heap for the top of the tree
    treetop: HeapORAMStorage<DataSize, MetaSize>,
    // The trusted merkle roots of trees rooted just below the treetop
    trusted_merkle_roots: Vec<Hash>,
    // A temporary scratch buffer for use when getting metadata from untrusted and validating it
    // This buffer contains metadata + extended_metadata for each checked out block (see README.md)
    meta_scratch_buffer: Vec<A8Bytes<Sum<MetaSize, ExtraMetaSize>>>,
    // An AES key
    aes_key: CipherGenericArray<u8, KeySize>,
    // The key we use when hashing ciphertexts to make merkle tree
    // Keeping this secret makes the hash functionally a mac
    hash_key: GenericArray<u8, KeySize>,
}

impl<DataSize, MetaSize> OcallORAMStorage<DataSize, MetaSize>
where
    DataSize: ArrayLength<u8> + PowerOfTwo + PartialDiv<U8>,
    MetaSize: ArrayLength<u8> + Add<ExtraMetaSize>,
    Sum<MetaSize, ExtraMetaSize>: ArrayLength<u8> + PartialDiv<U8>,
{
    /// Create a new oram storage object for count items, with particular RNG
    pub fn new<Rng: RngCore + CryptoRng>(count: u64, rng: &mut Rng) -> Self {
        assert!(count != 0);
        assert!(count & (count - 1) == 0, "count must be a power of two");

        let treetop_max_count: u64 = max(
            2u64,
            (1u64 << TREETOP_CACHING_THRESHOLD_LOG2.load(Ordering::SeqCst)) / DataSize::U64,
        );

        let mut allocation_id = 0u64;
        let treetop = if count <= treetop_max_count {
            // eprintln!("count = {} <= TREETOP_MAX_COUNT = {}", count, treetop_max_count);
            HeapORAMStorage::new(count)
        } else {
            // eprintln!("count = {} > TREETOP_MAX_COUNT = {}, we must allocate in
            // untrusted", count, treetop_max_count);
            allocation_id = helpers::allocate_ocall(
                count - treetop_max_count,
                DataSize::U64,
                MetaSize::U64 + ExtraMetaSize::U64,
            );
            if allocation_id == 0 {
                panic!("Untrusted could not allocate storage! count = {}, data_size = {}, meta_size + extra_meta_size = {}",
                       count - treetop_max_count,
                       DataSize::U64,
                       MetaSize::U64 + ExtraMetaSize::U64)
            }
            HeapORAMStorage::new(treetop_max_count)
        };

        let trusted_merkle_roots = if count <= treetop_max_count {
            Default::default()
        } else {
            vec![Default::default(); (treetop_max_count * 2) as usize]
        };

        let mut aes_key = GenericArray::<u8, KeySize>::default();
        rng.fill_bytes(aes_key.as_mut_slice());
        let mut hash_key = GenericArray::<u8, KeySize>::default();
        rng.fill_bytes(hash_key.as_mut_slice());

        Self {
            allocation_id,
            count,
            treetop_max_count,
            treetop,
            trusted_merkle_roots,
            meta_scratch_buffer: Default::default(),
            aes_key,
            hash_key,
        }
    }

    /// Get the treetop_max_count value for this storage object
    pub fn get_treetop_max_count(&self) -> u64 {
        self.treetop_max_count
    }
}

impl<DataSize, MetaSize> Drop for OcallORAMStorage<DataSize, MetaSize>
where
    DataSize: ArrayLength<u8> + PowerOfTwo + PartialDiv<U8>,
    MetaSize: ArrayLength<u8> + Add<ExtraMetaSize>,
    Sum<MetaSize, ExtraMetaSize>: ArrayLength<u8> + PartialDiv<U8>,
{
    fn drop(&mut self) {
        if self.allocation_id != 0 {
            let _lk = OCALL_REENTRANCY_MUTEX
                .lock()
                .expect("could not lock our mutex");
            helpers::release_ocall(self.allocation_id);
        }
    }
}

impl<DataSize, MetaSize> ORAMStorage<DataSize, MetaSize> for OcallORAMStorage<DataSize, MetaSize>
where
    DataSize: ArrayLength<u8> + PowerOfTwo + PartialDiv<U8>,
    MetaSize: ArrayLength<u8> + Add<ExtraMetaSize>,
    Sum<MetaSize, ExtraMetaSize>: ArrayLength<u8> + PartialDiv<U8>,
{
    fn len(&self) -> u64 {
        self.count
    }

    fn checkout(
        &mut self,
        index: u64,
        dest: &mut [A64Bytes<DataSize>],
        dest_meta: &mut [A8Bytes<MetaSize>],
    ) {
        assert_eq!(dest.len(), dest_meta.len());
        assert!(index > 0, "0 is not a valid TreeIndex");
        assert!(index < self.count, "index out of bounds");

        let mut indices: Vec<u64> = index.parents().collect();

        assert_eq!(indices.len(), dest.len());

        // First step: Do the part that's in the treetop
        let first_treetop_index = indices
            .iter()
            .position(|idx| idx < &self.treetop_max_count)
            .expect("should be unreachable, at least one thing should be in the treetop");

        self.treetop.checkout(
            indices[first_treetop_index],
            &mut dest[first_treetop_index..],
            &mut dest_meta[first_treetop_index..],
        );

        // Now do the part that's not in the treetop
        // If first_treetop_index == 0 then everything is in the treetop
        if first_treetop_index > 0 {
            // Subtract treetop_max_count from indices before sending to untrusted
            for idx in &mut indices[..first_treetop_index] {
                *idx -= self.treetop_max_count;
            }
            self.meta_scratch_buffer
                .resize_with(first_treetop_index, Default::default);

            {
                let _lk = OCALL_REENTRANCY_MUTEX
                    .lock()
                    .expect("could not lock our mutex");
                helpers::checkout_ocall(
                    self.allocation_id,
                    &indices[..first_treetop_index],
                    &mut dest[..first_treetop_index],
                    &mut self.meta_scratch_buffer,
                );
            }
            // Add treetop_max_count back to indices so that our calculations will be
            // correct
            for idx in &mut indices[..first_treetop_index] {
                *idx += self.treetop_max_count;
            }

            // We have to decrypt, checking the macs in the meta scratch buffer, and
            // ultimately set dest_meta[idx]
            let mut last_hash: Option<(u64, Hash)> = None;
            for idx in 0..first_treetop_index {
                // If untrusted gave us all 0's for the metadata, then the result is all zeroes
                // Otherwise we have to decrypt
                if self.meta_scratch_buffer[idx] == Default::default() {
                    dest[idx] = Default::default();
                    dest_meta[idx] = Default::default();
                    last_hash = Some((indices[idx], Default::default()));
                } else {
                    // Compute the hash for this block
                    let this_block_hash = compute_block_hash(
                        &self.hash_key,
                        &dest[idx],
                        indices[idx],
                        &self.meta_scratch_buffer[idx],
                    );

                    // Split extra_meta out of scratch buffer
                    let (meta, extra_meta) =
                        self.meta_scratch_buffer[idx].split_at_mut(MetaSize::USIZE);
                    let extra_meta = ExtraMeta::from(&*extra_meta);

                    // If this block has a child, check if its hash that we computed before matches
                    // metadata
                    if let Some((last_idx, last_hash)) = last_hash {
                        if last_idx & 1 == 0 {
                            if last_hash != extra_meta.left_child_hash {
                                panic!("authentication failed when checking out index[{}] = {}: left child hash {:?} != expected {:?}", idx, indices[idx], last_hash, extra_meta.left_child_hash);
                            }
                        } else if last_hash != extra_meta.right_child_hash {
                            panic!("authentication failed when checking out index[{}] = {}:, right child hash {:?} != expected {:?}", idx, indices[idx], last_hash, extra_meta.right_child_hash);
                        }
                    }

                    // Store this hash for next round
                    last_hash = Some((indices[idx], this_block_hash));

                    // Decrypt
                    let aes_nonce = make_aes_nonce(indices[idx], extra_meta.block_ctr);
                    let mut cipher = CipherType::new(&self.aes_key, &aes_nonce);
                    cipher.apply_keystream(&mut dest[idx]);
                    cipher.apply_keystream(meta);
                    dest_meta[idx].copy_from_slice(meta);
                }
            }

            // Check the last hash with the trusted merkle root storage
            // This unwrap is valid because if first_treetop_index is zero, then we didn't
            // enter this `if`
            let (last_idx, last_hash) = last_hash.expect("should not be empty at this point");
            assert!(
                bool::from(self.trusted_merkle_roots[last_idx as usize].ct_eq(&last_hash)),
                "authentication failed, trusted merkle root mismatch at {}",
                last_idx
            );
        }
    }

    fn checkin(
        &mut self,
        index: u64,
        src: &mut [A64Bytes<DataSize>],
        src_meta: &mut [A8Bytes<MetaSize>],
    ) {
        assert_eq!(src.len(), src_meta.len());
        assert!(index > 0);
        assert!(index < self.count, "index out of bounds");

        let mut indices: Vec<u64> = index.parents().collect();

        assert_eq!(indices.len(), src.len());

        let first_treetop_index = indices
            .iter()
            .position(|idx| idx < &self.treetop_max_count)
            .expect("should be unreachable, at least one thing should be in the treetop");

        self.treetop.checkin(
            indices[first_treetop_index],
            &mut src[first_treetop_index..],
            &mut src_meta[first_treetop_index..],
        );

        // If first_treetop_index == 0 then everything is in the treetop
        if first_treetop_index > 0 {
            self.meta_scratch_buffer
                .resize_with(first_treetop_index, Default::default);

            // We have to update the extra metadata, then encrypt the data and metadata,
            // then compute and store hash for next round.
            let mut last_hash: Option<(u64, Hash)> = None;
            for idx in 0..first_treetop_index {
                // Update the metadata field and extract the new block_ctr value so that we can
                // encrypt
                let block_ctr = {
                    // Split extra_meta out of scratch buffer
                    let (meta, extra_meta) =
                        self.meta_scratch_buffer[idx].split_at_mut(MetaSize::USIZE);

                    // Update the meta
                    meta.copy_from_slice(&src_meta[idx]);

                    // Update the extra_meta
                    let mut extra_meta_val = ExtraMeta::from(&*extra_meta);

                    // If this block has a child, update extra_meta check if its hash that we
                    // computed before matches metadata
                    if let Some((last_idx, last_hash)) = last_hash {
                        if last_idx & 1 == 0 {
                            extra_meta_val.left_child_hash = last_hash;
                        } else {
                            extra_meta_val.right_child_hash = last_hash;
                        }
                    }

                    // Update block_ctr value by incrementing it
                    extra_meta_val.block_ctr += 1;

                    // Serialize the ExtraMeta object to bytes and store them at extra_meta
                    let extra_meta_bytes = GenericArray::<u8, ExtraMetaSize>::from(&extra_meta_val);
                    extra_meta.copy_from_slice(extra_meta_bytes.as_slice());

                    // Return the block_ctr value to use for this encryption
                    extra_meta_val.block_ctr
                };

                // Encrypt the data that is supposed to be encrypted
                {
                    // Split meta out of scratch buffer
                    let (meta, _) = self.meta_scratch_buffer[idx].split_at_mut(MetaSize::USIZE);

                    // Encrypt
                    let aes_nonce = make_aes_nonce(indices[idx], block_ctr);
                    let mut cipher = CipherType::new(&self.aes_key, &aes_nonce);
                    cipher.apply_keystream(&mut src[idx]);
                    cipher.apply_keystream(meta);
                }

                // Compute the hash for this block and store it, to go with parent next round
                let this_block_hash = compute_block_hash(
                    &self.hash_key,
                    &src[idx],
                    indices[idx],
                    &self.meta_scratch_buffer[idx],
                );
                last_hash = Some((indices[idx], this_block_hash));
            }

            // The last one from the treetop goes in self.trusted_merkle_roots
            // This unwrap is valid because if first_treetop_index is zero, then we didn't
            // enter this `if`
            let (last_idx, last_hash) = last_hash.expect("should not be empty at this point");
            self.trusted_merkle_roots[last_idx as usize] = last_hash;

            // All extra-metas are done, now send it to untrusted for storage
            // Subtract treetop_max_count from indices before sending to untrusted
            for idx in &mut indices[..first_treetop_index] {
                *idx -= self.treetop_max_count;
            }
            let _lk = OCALL_REENTRANCY_MUTEX
                .lock()
                .expect("could not lock our mutex");
            helpers::checkin_ocall(
                self.allocation_id,
                &indices[..first_treetop_index],
                &src[..first_treetop_index],
                &self.meta_scratch_buffer,
            );
        }
    }
}

/// An ORAMStorageCreator for the Ocall-based storage type
pub struct OcallORAMStorageCreator;

impl<DataSize, MetaSize> ORAMStorageCreator<DataSize, MetaSize> for OcallORAMStorageCreator
where
    DataSize: ArrayLength<u8> + PowerOfTwo + PartialDiv<U8> + 'static,
    MetaSize: ArrayLength<u8> + Add<ExtraMetaSize> + 'static,
    Sum<MetaSize, ExtraMetaSize>: ArrayLength<u8> + PartialDiv<U8> + 'static,
{
    type Output = OcallORAMStorage<DataSize, MetaSize>;
    type Error = UntrustedStorageError;

    fn create<Rng: RngCore + CryptoRng>(
        size: u64,
        rng: &mut Rng,
    ) -> Result<Self::Output, Self::Error> {
        Ok(Self::Output::new(size, rng))
    }
}

/// An error type for when creating the OcallORAMStorage
// We actually panic on all of these errors, at least for now, because
// we can't really recover from them.
#[derive(Display, Debug)]
pub enum UntrustedStorageError {
    /// Untrusted could not allocate storage
    AllocationFailed,
}

// Helpers module contains wrappers that directly call to the unsafe ocalls.
//
// These shims exist partly so that we can more easily scope unsafe code, and
// also so that we can swap them out for testing
#[cfg(not(test))]
mod helpers {
    use super::*;

    // Helper for invoking the allocate OCALL safely
    //
    // Arguments:
    // * count: The number of (data, metadata) pairs that untrusted must agree to
    //   store
    // * data_size: The size of a data segment
    // * total_meta_size: The size of a meta segment
    //
    // Returns:
    // * An id number for the allocation. This is zero if the allocation failed.
    pub fn allocate_ocall(count: u64, data_size: u64, total_meta_size: u64) -> u64 {
        let mut allocation_id = 0u64;
        unsafe { allocate_oram_storage(count, data_size, total_meta_size, &mut allocation_id) }
        allocation_id
    }

    // Helper for invoking the release OCALL safely
    //
    // Arguments:
    // * id: The id of the allocation to release. Should not be zero or earlier
    //   released.
    pub fn release_ocall(id: u64) {
        unsafe { release_oram_storage(id) }
    }

    // Helper for invoking the checkout OCALL safely
    pub fn checkout_ocall<
        DataSize: ArrayLength<u8> + PartialDiv<U8>,
        MetaSize: ArrayLength<u8> + PartialDiv<U8>,
    >(
        id: u64,
        idx: &[u64],
        data: &mut [A64Bytes<DataSize>],
        meta: &mut [A8Bytes<MetaSize>],
    ) {
        debug_assert!(idx.len() == data.len());
        debug_assert!(idx.len() == meta.len());
        unsafe {
            super::checkout_oram_storage(
                id,
                idx.as_ptr(),
                idx.len(),
                data.as_mut_ptr() as *mut u64,
                data.len() * DataSize::USIZE / 8,
                meta.as_mut_ptr() as *mut u64,
                meta.len() * MetaSize::USIZE / 8,
            )
        }
    }
    // Helper for invoking the checkin OCALL safely
    pub fn checkin_ocall<
        DataSize: ArrayLength<u8> + PartialDiv<U8>,
        MetaSize: ArrayLength<u8> + PartialDiv<U8>,
    >(
        id: u64,
        idx: &[u64],
        data: &[A64Bytes<DataSize>],
        meta: &[A8Bytes<MetaSize>],
    ) {
        debug_assert!(idx.len() == data.len());
        debug_assert!(idx.len() == meta.len());
        unsafe {
            super::checkin_oram_storage(
                id,
                idx.as_ptr(),
                idx.len(),
                data.as_ptr() as *const u64,
                data.len() * DataSize::USIZE / 8,
                meta.as_ptr() as *const u64,
                meta.len() * MetaSize::USIZE / 8,
            )
        }
    }
}

// This stuff must match edl file
#[cfg(not(test))]
extern "C" {
    fn allocate_oram_storage(count: u64, data_size: u64, meta_size: u64, id: *mut u64);
    fn release_oram_storage(id: u64);
    fn checkout_oram_storage(
        id: u64,
        idx: *const u64,
        idx_len: usize,
        databuf: *mut u64,
        databuf_size: usize,
        metabuf: *mut u64,
        metabuf_size: usize,
    );
    fn checkin_oram_storage(
        id: u64,
        idx: *const u64,
        idx_len: usize,
        databuf: *const u64,
        databuf_size: usize,
        metabuf: *const u64,
        metabuf_size: usize,
    );
}

// Test version of the helpers to make it easier to test what trusted side does
// when untrusted memory is tampered with
#[cfg(test)]
mod helpers {
    use super::*;

    extern crate std;
    use lazy_static::lazy_static;
    use mc_util_test_helper::get_seeded_rng;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use typenum::{U1024, U16};

    fn a64_bytes<N: ArrayLength<u8>>(src: u8) -> A64Bytes<N> {
        let mut result = A64Bytes::<N>::default();
        for byte in result.as_mut_slice() {
            *byte = src;
        }
        result
    }

    fn a8_bytes<N: ArrayLength<u8>>(src: u8) -> A8Bytes<N> {
        let mut result = A8Bytes::<N>::default();
        for byte in result.as_mut_slice() {
            *byte = src;
        }
        result
    }

    // Test version of UntrustedAllocation (see Untrusted crate)
    #[derive(Default)]
    struct Allocation {
        #[allow(unused)]
        count: u64,
        data_size: u64,
        meta_size: u64,
        data: Vec<u8>,
        meta: Vec<u8>,
    }

    impl Allocation {
        // Make a new mock allocation object
        pub fn new(count: u64, data_size: u64, meta_size: u64) -> Self {
            let data = vec![0u8; (count * data_size) as usize];
            let meta = vec![0u8; (count * meta_size) as usize];
            Self {
                count,
                data_size,
                meta_size,
                data,
                meta,
            }
        }
    }

    lazy_static! {
        static ref ALLOCATIONS: Mutex<Vec<Allocation>> = Mutex::new(Vec::new());
    }

    // Mocks the allocation ocall
    pub fn allocate_ocall(count: u64, data_size: u64, total_meta_size: u64) -> u64 {
        let mut allocations = ALLOCATIONS.lock().unwrap();

        // Now actually make the allocation
        allocations.push(Allocation::new(count, data_size, total_meta_size));

        // The id we return is the length of the vector now (index + 1)
        allocations.len() as u64
    }

    // Mocks the release ocall
    // This is a no-op for purposes of testing
    pub fn release_ocall(_id: u64) {}

    // Mocks the checkout ocall
    pub fn checkout_ocall<
        DataSize: ArrayLength<u8> + PartialDiv<U8>,
        MetaSize: ArrayLength<u8> + PartialDiv<U8>,
    >(
        id: u64,
        idx: &[u64],
        data: &mut [A64Bytes<DataSize>],
        meta: &mut [A8Bytes<MetaSize>],
    ) {
        debug_assert!(idx.len() == data.len());
        debug_assert!(idx.len() == meta.len());

        let allocations = ALLOCATIONS.lock().unwrap();
        let allocation = &allocations[id as usize - 1];

        debug_assert!(allocation.data_size == DataSize::U64);
        debug_assert!(allocation.meta_size == MetaSize::U64);

        for (x, idx) in idx.iter().enumerate() {
            let byte_index = (idx * DataSize::U64) as usize;
            (&mut data[x])
                .copy_from_slice(&allocation.data[byte_index..byte_index + DataSize::USIZE]);
            let byte_index = (idx * MetaSize::U64) as usize;
            (&mut meta[x])
                .copy_from_slice(&allocation.meta[byte_index..byte_index + MetaSize::USIZE]);
        }
    }

    // Mocks the checkin ocall
    pub fn checkin_ocall<
        DataSize: ArrayLength<u8> + PartialDiv<U8>,
        MetaSize: ArrayLength<u8> + PartialDiv<U8>,
    >(
        id: u64,
        idx: &[u64],
        data: &[A64Bytes<DataSize>],
        meta: &[A8Bytes<MetaSize>],
    ) {
        debug_assert!(idx.len() == data.len());
        debug_assert!(idx.len() == meta.len());

        let mut allocations = ALLOCATIONS.lock().unwrap();
        let allocation = &mut allocations[id as usize - 1];

        debug_assert!(allocation.data_size == DataSize::U64);
        debug_assert!(allocation.meta_size == MetaSize::U64);

        for (x, idx) in idx.iter().enumerate() {
            let byte_index = (idx * DataSize::U64) as usize;
            allocation.data[byte_index..byte_index + DataSize::USIZE]
                .copy_from_slice(data[x].as_ref());
            let byte_index = (idx * MetaSize::U64) as usize;
            allocation.meta[byte_index..byte_index + MetaSize::USIZE]
                .copy_from_slice(meta[x].as_ref());
        }
    }

    // Test what happens when we exercise the ORAM
    // This is simlar to the integration test in `mc-fog-ocall-oram-storage-testing`
    #[test]
    fn exercise_oram_storage_shims() {
        let mut rng = get_seeded_rng();
        type StorageType = OcallORAMStorage<U1024, U16>;

        // Set tree-top level to 1KB
        TREETOP_CACHING_THRESHOLD_LOG2.store(10, Ordering::SeqCst);

        let mut st = StorageType::new(131072, &mut rng);

        let mut data_scratch = vec![A64Bytes::<U1024>::default(); 17];
        let mut meta_scratch = vec![A8Bytes::<U16>::default(); 17];

        // Write 1's along branch at 131072 - 1
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // Initially the data might not be zeroed, but the meta must be
            for meta in meta_scratch.iter() {
                assert_eq!(meta, &a8_bytes(0));
            }

            // Write to the data and metadata
            for data in data_scratch.iter_mut() {
                *data = a64_bytes(1);
            }
            for meta in meta_scratch.iter_mut() {
                *meta = a8_bytes(1);
            }

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }

        // Check that 1's are along branch at 131072 - 1
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // Now both should be initialized
            for data in data_scratch.iter() {
                assert_eq!(data, &a64_bytes(1));
            }
            for meta in meta_scratch.iter() {
                assert_eq!(meta, &a8_bytes(1));
            }

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }

        // Write 2's along branch at 131072 - 4
        {
            st.checkout(131072 - 4, &mut data_scratch, &mut meta_scratch);

            // The first two data (lowest in branch) might not be initialized
            assert_eq!(data_scratch[0], a64_bytes(0));
            for data in &data_scratch[2..17] {
                assert_eq!(data, &a64_bytes(1));
            }

            // The first two meta should be zeros
            assert_eq!(meta_scratch[0], a8_bytes(0));
            assert_eq!(meta_scratch[1], a8_bytes(0));
            for meta in &meta_scratch[2..] {
                assert_eq!(meta, &a8_bytes(1));
            }

            // write 2's
            for data in data_scratch.iter_mut() {
                *data = a64_bytes(2);
            }
            for meta in meta_scratch.iter_mut() {
                *meta = a8_bytes(2);
            }

            st.checkin(131072 - 4, &mut data_scratch, &mut meta_scratch);
        }

        // Check that the 2's are visible along branch 131072 - 1, and some 1's
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // the first two data should be 1's
            assert_eq!(data_scratch[0], a64_bytes(1));
            assert_eq!(data_scratch[1], a64_bytes(1));
            for data in &data_scratch[2..] {
                assert_eq!(data, &a64_bytes(2));
            }

            // the first two meta should be 1's
            assert_eq!(meta_scratch[0], a8_bytes(1));
            assert_eq!(meta_scratch[1], a8_bytes(1));
            for meta in &meta_scratch[2..] {
                assert_eq!(meta, &a8_bytes(2));
            }

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }

        // Write 3's along branch 131072 / 2 + 1, and check if 1's and 2's are visible
        {
            st.checkout(131072 / 2 + 1, &mut data_scratch, &mut meta_scratch);

            assert_eq!(data_scratch[16], a64_bytes(2));
            assert_eq!(meta_scratch[16], a8_bytes(2));
            for meta in &meta_scratch[0..16] {
                assert_eq!(meta, &a8_bytes(0));
            }

            // write 3's
            for data in data_scratch.iter_mut() {
                *data = a64_bytes(3);
            }
            for meta in meta_scratch.iter_mut() {
                *meta = a8_bytes(3);
            }

            st.checkin(131072 / 2 + 1, &mut data_scratch, &mut meta_scratch);
        }

        // Check that 3's are along branch at 131072/2 + 1
        {
            st.checkout(131072 / 2 + 1, &mut data_scratch, &mut meta_scratch);

            for data in data_scratch.iter() {
                assert_eq!(data, &a64_bytes(3));
            }
            for meta in meta_scratch.iter() {
                assert_eq!(meta, &a8_bytes(3));
            }

            st.checkin(131072 / 2 + 1, &mut data_scratch, &mut meta_scratch);
        }

        // Check that 1's, 2's and 3's are visible along branch 131072 - 1
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // the first two data should be 1's
            assert_eq!(data_scratch[0], a64_bytes(1));
            assert_eq!(data_scratch[1], a64_bytes(1));
            for data in &data_scratch[2..16] {
                assert_eq!(data, &a64_bytes(2));
            }
            // this 3 at the root should be visible
            assert_eq!(data_scratch[16], a64_bytes(3));

            // the first two meta should be 1's
            assert_eq!(meta_scratch[0], a8_bytes(1));
            assert_eq!(meta_scratch[1], a8_bytes(1));
            for meta in &meta_scratch[2..16] {
                assert_eq!(meta, &a8_bytes(2));
            }
            // this 3 at the root should be visible
            assert_eq!(meta_scratch[16], a8_bytes(3));

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }
    }

    // Test what happens when we start screwing with the untrusted memory,
    // by hammering it with junk value
    #[test]
    fn exercise_oram_storage_hammer_data() {
        let mut rng = get_seeded_rng();
        type StorageType = OcallORAMStorage<U1024, U16>;

        // Set tree-top level to 1KB
        TREETOP_CACHING_THRESHOLD_LOG2.store(10, Ordering::SeqCst);

        let mut st = StorageType::new(131072, &mut rng);

        let allocation_id = st.allocation_id;

        let mut data_scratch = vec![A64Bytes::<U1024>::default(); 17];
        let mut meta_scratch = vec![A8Bytes::<U16>::default(); 17];

        // Write 1's along branch at 131072 - 1
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // Initially the data might not be zeroed, but the meta must be
            for meta in meta_scratch.iter() {
                assert_eq!(meta, &a8_bytes(0));
            }

            // Write to the data and metadata
            for data in data_scratch.iter_mut() {
                *data = a64_bytes(1);
            }
            for meta in meta_scratch.iter_mut() {
                *meta = a8_bytes(1);
            }

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }

        // Check that 1's are along branch at 131072 - 1
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // Now both should be initialized
            for data in data_scratch.iter() {
                assert_eq!(data, &a64_bytes(1));
            }
            for meta in meta_scratch.iter() {
                assert_eq!(meta, &a8_bytes(1));
            }

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }

        // Write 2's along branch at 131072 - 4
        {
            st.checkout(131072 - 4, &mut data_scratch, &mut meta_scratch);

            // The first two data (lowest in branch) might not be initialized
            assert_eq!(data_scratch[0], a64_bytes(0));
            for data in &data_scratch[2..17] {
                assert_eq!(data, &a64_bytes(1));
            }

            // The first two meta should be zeros
            assert_eq!(meta_scratch[0], a8_bytes(0));
            assert_eq!(meta_scratch[1], a8_bytes(0));
            for meta in &meta_scratch[2..] {
                assert_eq!(meta, &a8_bytes(1));
            }

            // write 2's
            for data in data_scratch.iter_mut() {
                *data = a64_bytes(2);
            }
            for meta in meta_scratch.iter_mut() {
                *meta = a8_bytes(2);
            }

            st.checkin(131072 - 4, &mut data_scratch, &mut meta_scratch);
        }

        // Check that the 2's are visible along branch 131072 - 1, and some 1's
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // the first two data should be 1's
            assert_eq!(data_scratch[0], a64_bytes(1));
            assert_eq!(data_scratch[1], a64_bytes(1));
            for data in &data_scratch[2..] {
                assert_eq!(data, &a64_bytes(2));
            }

            // the first two meta should be 1's
            assert_eq!(meta_scratch[0], a8_bytes(1));
            assert_eq!(meta_scratch[1], a8_bytes(1));
            for meta in &meta_scratch[2..] {
                assert_eq!(meta, &a8_bytes(2));
            }

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }

        // Now hammer the untrusted data
        {
            let mut allocations = ALLOCATIONS.lock().unwrap();
            let allocation = &mut allocations[allocation_id as usize - 1];

            for item in allocation.data.iter_mut() {
                *item = 16;
            }
        }

        // Now we should panic when we checkout again
        assert!(catch_unwind(AssertUnwindSafe(|| st.checkout(
            131072 / 2 + 1,
            &mut data_scratch,
            &mut meta_scratch
        )))
        .is_err());
    }

    // Test what happens when we start screwing with the untrusted memory,
    // by hammering it with junk value
    #[test]
    fn exercise_oram_storage_clear_data() {
        let mut rng = get_seeded_rng();
        type StorageType = OcallORAMStorage<U1024, U16>;

        // Set tree-top level to 1KB
        TREETOP_CACHING_THRESHOLD_LOG2.store(10, Ordering::SeqCst);

        let mut st = StorageType::new(131072, &mut rng);

        let allocation_id = st.allocation_id;

        let mut data_scratch = vec![A64Bytes::<U1024>::default(); 17];
        let mut meta_scratch = vec![A8Bytes::<U16>::default(); 17];

        // Write 1's along branch at 131072 - 1
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // Initially the data might not be zeroed, but the meta must be
            for meta in meta_scratch.iter() {
                assert_eq!(meta, &a8_bytes(0));
            }

            // Write to the data and metadata
            for data in data_scratch.iter_mut() {
                *data = a64_bytes(1);
            }
            for meta in meta_scratch.iter_mut() {
                *meta = a8_bytes(1);
            }

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }

        // Check that 1's are along branch at 131072 - 1
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // Now both should be initialized
            for data in data_scratch.iter() {
                assert_eq!(data, &a64_bytes(1));
            }
            for meta in meta_scratch.iter() {
                assert_eq!(meta, &a8_bytes(1));
            }

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }

        // Write 2's along branch at 131072 - 4
        {
            st.checkout(131072 - 4, &mut data_scratch, &mut meta_scratch);

            // The first two data (lowest in branch) might not be initialized
            assert_eq!(data_scratch[0], a64_bytes(0));
            for data in &data_scratch[2..17] {
                assert_eq!(data, &a64_bytes(1));
            }

            // The first two meta should be zeros
            assert_eq!(meta_scratch[0], a8_bytes(0));
            assert_eq!(meta_scratch[1], a8_bytes(0));
            for meta in &meta_scratch[2..] {
                assert_eq!(meta, &a8_bytes(1));
            }

            // write 2's
            for data in data_scratch.iter_mut() {
                *data = a64_bytes(2);
            }
            for meta in meta_scratch.iter_mut() {
                *meta = a8_bytes(2);
            }

            st.checkin(131072 - 4, &mut data_scratch, &mut meta_scratch);
        }

        // Check that the 2's are visible along branch 131072 - 1, and some 1's
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // the first two data should be 1's
            assert_eq!(data_scratch[0], a64_bytes(1));
            assert_eq!(data_scratch[1], a64_bytes(1));
            for data in &data_scratch[2..] {
                assert_eq!(data, &a64_bytes(2));
            }

            // the first two meta should be 1's
            assert_eq!(meta_scratch[0], a8_bytes(1));
            assert_eq!(meta_scratch[1], a8_bytes(1));
            for meta in &meta_scratch[2..] {
                assert_eq!(meta, &a8_bytes(2));
            }

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }

        // Now clear the untrusted data
        {
            let mut allocations = ALLOCATIONS.lock().unwrap();
            let allocation = &mut allocations[allocation_id as usize - 1];

            for item in allocation.data.iter_mut() {
                *item = 0;
            }
        }

        // Now we should panic when we checkout again
        assert!(catch_unwind(AssertUnwindSafe(|| st.checkout(
            131072 / 2 + 1,
            &mut data_scratch,
            &mut meta_scratch
        )))
        .is_err());
    }

    // Test what happens when we start screwing with the untrusted memory,
    // by hammering the metadata with junk value
    #[test]
    fn exercise_oram_storage_hammer_metadata() {
        let mut rng = get_seeded_rng();
        type StorageType = OcallORAMStorage<U1024, U16>;

        // Set tree-top level to 1KB
        TREETOP_CACHING_THRESHOLD_LOG2.store(10, Ordering::SeqCst);

        let mut st = StorageType::new(131072, &mut rng);

        let allocation_id = st.allocation_id;

        let mut data_scratch = vec![A64Bytes::<U1024>::default(); 17];
        let mut meta_scratch = vec![A8Bytes::<U16>::default(); 17];

        // Write 1's along branch at 131072 - 1
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // Initially the data might not be zeroed, but the meta must be
            for meta in meta_scratch.iter() {
                assert_eq!(meta, &a8_bytes(0));
            }

            // Write to the data and metadata
            for data in data_scratch.iter_mut() {
                *data = a64_bytes(1);
            }
            for meta in meta_scratch.iter_mut() {
                *meta = a8_bytes(1);
            }

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }

        // Check that 1's are along branch at 131072 - 1
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // Now both should be initialized
            for data in data_scratch.iter() {
                assert_eq!(data, &a64_bytes(1));
            }
            for meta in meta_scratch.iter() {
                assert_eq!(meta, &a8_bytes(1));
            }

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }

        // Write 2's along branch at 131072 - 4
        {
            st.checkout(131072 - 4, &mut data_scratch, &mut meta_scratch);

            // The first two data (lowest in branch) might not be initialized
            assert_eq!(data_scratch[0], a64_bytes(0));
            for data in &data_scratch[2..17] {
                assert_eq!(data, &a64_bytes(1));
            }

            // The first two meta should be zeros
            assert_eq!(meta_scratch[0], a8_bytes(0));
            assert_eq!(meta_scratch[1], a8_bytes(0));
            for meta in &meta_scratch[2..] {
                assert_eq!(meta, &a8_bytes(1));
            }

            // write 2's
            for data in data_scratch.iter_mut() {
                *data = a64_bytes(2);
            }
            for meta in meta_scratch.iter_mut() {
                *meta = a8_bytes(2);
            }

            st.checkin(131072 - 4, &mut data_scratch, &mut meta_scratch);
        }

        // Check that the 2's are visible along branch 131072 - 1, and some 1's
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // the first two data should be 1's
            assert_eq!(data_scratch[0], a64_bytes(1));
            assert_eq!(data_scratch[1], a64_bytes(1));
            for data in &data_scratch[2..] {
                assert_eq!(data, &a64_bytes(2));
            }

            // the first two meta should be 1's
            assert_eq!(meta_scratch[0], a8_bytes(1));
            assert_eq!(meta_scratch[1], a8_bytes(1));
            for meta in &meta_scratch[2..] {
                assert_eq!(meta, &a8_bytes(2));
            }

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }

        // Now hammer the untrusted metadata
        {
            let mut allocations = ALLOCATIONS.lock().unwrap();
            let allocation = &mut allocations[allocation_id as usize - 1];

            for item in allocation.meta.iter_mut() {
                *item = 19;
            }
        }

        // Now we should panic when we checkout again
        assert!(catch_unwind(AssertUnwindSafe(|| st.checkout(
            131072 / 2 + 1,
            &mut data_scratch,
            &mut meta_scratch
        )))
        .is_err());
    }

    // Test what happens when we start screwing with the untrusted memory,
    // by clearing the metadata
    #[test]
    fn exercise_oram_storage_clear_metadata() {
        let mut rng = get_seeded_rng();
        type StorageType = OcallORAMStorage<U1024, U16>;

        // Set tree-top level to 1KB
        TREETOP_CACHING_THRESHOLD_LOG2.store(10, Ordering::SeqCst);

        let mut st = StorageType::new(131072, &mut rng);

        let allocation_id = st.allocation_id;

        let mut data_scratch = vec![A64Bytes::<U1024>::default(); 17];
        let mut meta_scratch = vec![A8Bytes::<U16>::default(); 17];

        // Write 1's along branch at 131072 - 1
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // Initially the data might not be zeroed, but the meta must be
            for meta in meta_scratch.iter() {
                assert_eq!(meta, &a8_bytes(0));
            }

            // Write to the data and metadata
            for data in data_scratch.iter_mut() {
                *data = a64_bytes(1);
            }
            for meta in meta_scratch.iter_mut() {
                *meta = a8_bytes(1);
            }

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }

        // Check that 1's are along branch at 131072 - 1
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // Now both should be initialized
            for data in data_scratch.iter() {
                assert_eq!(data, &a64_bytes(1));
            }
            for meta in meta_scratch.iter() {
                assert_eq!(meta, &a8_bytes(1));
            }

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }

        // Write 2's along branch at 131072 - 4
        {
            st.checkout(131072 - 4, &mut data_scratch, &mut meta_scratch);

            // The first two data (lowest in branch) might not be initialized
            assert_eq!(data_scratch[0], a64_bytes(0));
            for data in &data_scratch[2..17] {
                assert_eq!(data, &a64_bytes(1));
            }

            // The first two meta should be zeros
            assert_eq!(meta_scratch[0], a8_bytes(0));
            assert_eq!(meta_scratch[1], a8_bytes(0));
            for meta in &meta_scratch[2..] {
                assert_eq!(meta, &a8_bytes(1));
            }

            // write 2's
            for data in data_scratch.iter_mut() {
                *data = a64_bytes(2);
            }
            for meta in meta_scratch.iter_mut() {
                *meta = a8_bytes(2);
            }

            st.checkin(131072 - 4, &mut data_scratch, &mut meta_scratch);
        }

        // Check that the 2's are visible along branch 131072 - 1, and some 1's
        {
            st.checkout(131072 - 1, &mut data_scratch, &mut meta_scratch);

            // the first two data should be 1's
            assert_eq!(data_scratch[0], a64_bytes(1));
            assert_eq!(data_scratch[1], a64_bytes(1));
            for data in &data_scratch[2..] {
                assert_eq!(data, &a64_bytes(2));
            }

            // the first two meta should be 1's
            assert_eq!(meta_scratch[0], a8_bytes(1));
            assert_eq!(meta_scratch[1], a8_bytes(1));
            for meta in &meta_scratch[2..] {
                assert_eq!(meta, &a8_bytes(2));
            }

            st.checkin(131072 - 1, &mut data_scratch, &mut meta_scratch);
        }

        // Now clear the untrusted metadata
        {
            let mut allocations = ALLOCATIONS.lock().unwrap();
            let allocation = &mut allocations[allocation_id as usize - 1];

            for item in allocation.meta.iter_mut() {
                *item = 0;
            }
        }

        // Now we should panic when we checkout again
        assert!(catch_unwind(AssertUnwindSafe(|| st.checkout(
            131072 / 2 + 1,
            &mut data_scratch,
            &mut meta_scratch
        )))
        .is_err());
    }
}
