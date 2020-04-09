// Copyright (c) 2018-2020 MobileCoin Inc.

pub use sgx_libc_types::Frame;
pub use std::ffi::CString;
/// This module defines a trait SymbolContext that defines the API that we
/// expect from any implementation of backtrace symbolication.
///
/// This follows rust std API, see sys/backtrace, where the GNU
/// libbacktrace library is used for this functionality.
///
pub use std::io;

/// In addition to SymbolContext, the Symbolicator should also implement:
///
/// Attempts to load the enclave at given path and read the symbol table
/// Initialization is permitted to fail and yield a SymbolContext in a null
/// state. The implementation may assume that the CString lives longer than it.
/// fn new(enclave_path: &CString) -> Self;
///
/// Creates a SymbolContext in the null state
/// fn new_null() -> Self;
///
pub trait SymbolContext {
    /// Checks if the backtrace context is in a null state, indicating that
    /// initialization failed. This typically means the file could not be
    /// opened.
    fn is_null(&self) -> bool;

    /// Takes a closure, and calls it for each file/line no pair associated to
    /// the symbol. Early escapes with an io::Error if the closure returns an
    /// error.
    ///
    /// If the symbol cannot be resolved, the closure is not called.
    ///
    /// Arguments:
    /// frame: A backtrace frame to resolve
    /// f: A closure taking a filename and line number, returning io::Result<()>
    ///
    /// Returns:
    /// io::Result<bool>. True if  lookup was successful, false if it failed.
    ///                   err only if closure returned an error
    fn foreach_symbol_fileline(
        &mut self,
        frame: &Frame,
        f: &mut dyn FnMut(&[u8], u32) -> io::Result<()>,
    ) -> io::Result<bool>;

    /// Takes a frame, attempts to resolve the symbol, and passes Option<&str>
    /// to the given closure.
    ///
    /// There's not much reason to use a closure here instead of just returning
    /// Option<&str> but we could imagine that if libbacktrace stopped leaking
    /// everything, then these `str` would have bounded lifetime, and so a
    /// closure would help resolve the lifetime issues.
    ///
    /// Note that in rust std this closure parameter has type FnOnce but that
    /// causes technical issues:
    /// - FnOnce can only be called in a way that consumes the object
    /// - We cannot pass an FnOnce by value on the stack because its size is not
    ///   known. If we want to pass it it must be a reference.
    fn resolve_symname(
        &mut self,
        frame: &Frame,
        f: &mut dyn FnMut(Option<&str>) -> io::Result<()>,
    ) -> io::Result<()>;
}
