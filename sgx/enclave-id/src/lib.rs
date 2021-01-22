// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};
use mc_sgx_types::sgx_enclave_id_t;

static ENCLAVE_ID: AtomicU64 = AtomicU64::new(0);

pub fn get_enclave_id() -> sgx_enclave_id_t {
    ENCLAVE_ID.load(Ordering::SeqCst)
}

pub fn set_enclave_id(id: sgx_enclave_id_t) {
    let old_val = ENCLAVE_ID.swap(id, Ordering::SeqCst);
    if old_val != 0 {
        panic!(
            "sgx_enclave_id was doubly initialized: old val: {} new_val: {}",
            old_val, id
        );
    }
}
