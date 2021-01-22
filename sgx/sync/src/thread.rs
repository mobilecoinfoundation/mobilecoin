// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_sgx_types::{sgx_thread_self, sgx_thread_t};

///
/// The thread_self function returns the unique thread identification.
///
/// # Description
///
/// The function is a simple wrap of get_thread_data() provided in the tRTS,
/// which provides a trusted thread unique identifier.
///
/// # Requirements
///
/// Library: libsgx_tstdc.a
///
/// # Return value
///
/// The return value cannot be NULL and is always valid as long as it is invoked by a thread inside the enclave.
///
pub fn thread_self() -> sgx_thread_t {
    unsafe { sgx_thread_self() }
}
