// Copyright (c) 2018-2020 MobileCoin Inc.

/// Implementation for report_backtrace OCALL, which attempts to
/// symbolicate the frames from the enclave, and print them to stderr
pub use mc_sgx_libc_types::Frame;
use mc_sgx_types::sgx_enclave_id_t;

use std::ffi::CString;

use std::{collections::HashMap, io::stderr, path::PathBuf, slice, sync::Mutex};

// Helper cache data structure
mod cache;
use self::cache::Cache;

// This is mostly a copy-paste of src/libstd/sys_common/backtrace.rs with small
// differences
mod printing;

// Defines SymbolContext trait that encapsulates the implementation of symbol
// lookup in the enclave.so file
mod symbol_context;
use self::symbol_context::SymbolContext;

// Module provides an implementation of SymbolContext trait.
// The implementor object must be a pub struct named Symbolicator.
// The Symbolicator must also be marked with Send trait.
// Even if rust does not automatically do this, it will generally be okay
// to mark it so manually,
// because Mutex<ContextCache> below prevents multithreaded access.
//
// This module is expected to be exchanged using cfg if necessary to compile
// with different implementations for different targets.
//
mod symbols;
use self::symbols::Symbolicator;

// Maintain a map from enclave id to its path, so that on the other side (ocall),
// we can do the symbolication. This info comes from the constructor of mc_sgx_urts::SgxEnclave.
lazy_static! {
    pub static ref ENCLAVE_PATH_MAP: Mutex<HashMap<sgx_enclave_id_t, PathBuf>> =
        Mutex::new(Default::default());
}

#[no_mangle]
pub unsafe extern "C" fn report_backtrace(
    eid: sgx_enclave_id_t,
    frames_ptr: *const Frame,
    num_frames: usize,
) {
    report_backtrace_impl(eid, slice::from_raw_parts(frames_ptr, num_frames));
}

fn report_backtrace_impl(eid: sgx_enclave_id_t, frames: &[Frame]) {
    symbolicate_and_print_backtrace(eid, frames);
}

fn symbolicate_and_print_backtrace(eid: sgx_enclave_id_t, frames: &[Frame]) {
    let lk = ENCLAVE_PATH_MAP
        .lock()
        .expect("Could not lock ENCLAVE_PATH_MAP!");
    let enclave_path = lk.get(&eid).unwrap_or_else(|| panic!("Enclave path was unknown for eid = {}, eid=0 indicates sgx_enclave_id was not initialized. Otherwise are you using mc_sgx_urts::SgxEnclave?", eid));

    // Gnu backtrace is (1) leaky (2) not threadsafe
    // So we must cache its contexts and put them behind a mutex

    lazy_static! {
        static ref CACHE: Mutex<ContextCache> = Mutex::new(ContextCache::new());
    }

    let mut lk = CACHE.lock().expect("Could not lock context cache!");
    let ctxt = lk.get(enclave_path.clone());
    if ctxt.is_null() {
        eprintln!("(could not load symbols from '{}')", enclave_path.display());
    } else {
        eprintln!("(loading symbols from '{}')", enclave_path.display());
    }
    drop(printing::print(&mut stderr(), frames, ctxt));
}

// ContextCache provides caching of PathBuf -> Symbolicator new function
pub struct ContextCache(Cache<PathBuf, Symbolicator>);

impl ContextCache {
    // Create a cache, with the proper lambda callback installed
    pub fn new() -> Self {
        Self(Cache::new(Box::new(|path: &PathBuf| {
            // Convert path to a CString
            use std::os::unix::ffi::OsStrExt;
            let path_cstr = CString::new(path.as_os_str().as_bytes()).unwrap();
            // Try to give helpful guidance if there is no enclave path
            if path_cstr.as_bytes().len() <= 1 {
                eprintln!("Enclave path is not available, cannot symbolicate backtrace. Are you using mc_sgx_urts::SgxEnclave?");
                return Symbolicator::new_null();
            }

            Symbolicator::new(&path_cstr)
        })))
    }

    // Lookup a SymbolContext, return a &mut
    pub fn get(&mut self, path: PathBuf) -> &mut Symbolicator {
        self.0.get(path)
    }
}
