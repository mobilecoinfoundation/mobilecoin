// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains a collection of general utilities useful in creating a
//! C-FFI API to code written in Rust.
//!
//! Types in this module are not specific to MobileCoin and are generally
//! applicable to anyone writing such an API, although they are provided here
//! for the time being for the sake of convenience.
//!
//! # Naming
//!
//! `Ffi`-prefixed types (`FfiOwnedPtr` and family, `FfiOwnedStr` and family)
//! are types that are `#[repr(transparent)]` wrappers around an underlying
//! C-compatible type. These types can be used directly as the type of
//! parameters and the return type of `extern "C"`-style functions and as fields
//! of C-style structs used in that same way. These types are guaranteed to have
//! a memory layout that is C-compatible and offer safety guarantees within safe
//! Rust that the raw underlying type would not have provided.
//!
//! # Memory Allocation
//!
//! As a rule, all memory (in particular, heap memory) should be deallocated by
//! the memory allocator that initially allocated the memory. Namely, whenever
//! an allocated "owned" object is allocated by Rust code and passed back to
//! foreign code, that foreign code takes ownership (takes over responsibility
//! for disposing of the object), with the caveat that the actual memory
//! deallocation needs be be performed by the original allocator. In practice,
//! this usually means that any time foreign code calls a Rust FFI function that
//! returns an owned object, the foreign code becomes responsible for later
//! calling the corresponding "free" function, usually taking the form of
//! `extern fn mc_<type_name>_free`.
//!
//! `FfiOwnedStr` and family are C-strings represented by the equivalent of C's
//! `char *`/`const char *` in non-Rust code and are intended to be allocated
//! within Rust but with contents accessible to foreign code.
//!
//! `FfiOwnedPtr` and family are pointer types whose pointed-to memory could
//! either have been allocated by foreign code and passed to Rust, or by Rust
//! code and passed back to foreign code, depending on context.
//!
//! # Lifetimes
//!
//! `FfiOwnedStr` and `FfiOwnedPtr` and their respective families are type that
//! are intended to manage object ownership in the context of an FFI API, while
//! their counterparts (`FfiStr`, `FfiRefPtr`, etc) are intended to manage
//! lifetimes of references (regardless of whether the pointed-to memory is
//! owned by an `FfiOwnedStr`/`FfiOwnedPtr`-style object or managed by something
//! else entirely).
//!
//! It should be noted that lifetime parameters to a `extern fn`-style function
//! that's called by foreign code is likely not required by the foreign compiler
//! to adhere to Rust's lifetime rules. This means that, e.g. a temporary value
//! in foreign code that is passed to Rust FFI function accepting a parameter
//! with a `'static` lifetime requirement is unlikely to cause the foreign
//! compiler to issue a compiler-time error. To lessen the risk of Rust code
//! retaining a reference to memory allocated by foreign code longer than the
//! foreign code expects, parameters to FFI Rust functions should use lifetimes
//! that are determined by the caller of the function anytime a lifetime is
//! required for a reference to memory allocated on the foreign side of the FFI
//! boundary.
//!
//! In practice this means that the lifetime should be elided where possible, or
//! a lifetime of `'_` should be used. In cases where neither is possible, a
//! lifetime template parameter should be added to the function. As an example,
//! to illustrate, one of the following techniques should be used:
//!  * `extern "C" fn ffi_func_name(param: FfiRefPtr<ForeignType>)`
//!  * `extern "C" fn ffi_func_name(param: FfiRefPtr<'_, ForeignType>)`
//!  * `extern "C" fn ffi_func_name<'a>(param: FfiRefPtr<'a, ForeignType>)`

pub use ffi_owned_ptr::*;
pub use ffi_ref_ptr::*;
pub use ffi_str::*;

mod ffi_owned_ptr;
mod ffi_ref_ptr;
mod ffi_str;
