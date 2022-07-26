// Copyright (c) 2018-2022 The MobileCoin Foundation

//! This module contains a collection of general utilities useful in creating a
//! C-FFI API to code written in Rust.
//!
//! # Naming
//!
//! `McBuffer`, `McMutableBuffer`, and `McError` are types that are represented
//! as C structs and meant to be declared as such in the equivalent of a C
//! header. The fields of these types are guaranteed to be visible and
//! accessible from foreign code.
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
//! `McError` is a non-opaque type intended to be allocated within Rust but with
//! contents accessible to foreign code. `McError` is represented as a C-style
//! struct in non-Rust code.
//!
//! `McBuffer` and `McMutableBuffer` are intended to be allocated by foreign
//! code and passed to Rust. The lifetime of this object on the Rust side should
//! only be for the lifetime of the function. Rust code should not maintain a
//! reference to objects of this type or access the pointed-to memory after the
//! FFI function has ended.

#![macro_use]

pub(crate) mod macros;

mod boundary;
mod buffer;
mod data;
mod error;
mod into_ffi;
mod rng;
mod string;

pub use self::{
    buffer::{McBuffer, McMutableBuffer},
    data::{mc_data_free, mc_data_get_bytes, McData},
    error::{mc_error_free, McError},
    rng::{CallbackRng, FfiCallbackRng, McRngCallback, SdkRng},
    string::mc_string_free,
};

pub(crate) use self::{
    boundary::{ffi_boundary, ffi_boundary_with_error},
    into_ffi::{FfiTryFrom, FfiTryInto, FromFfi, IntoFfi, TryFromFfi},
};
