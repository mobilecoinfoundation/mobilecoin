// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]
// Needed for a #[may_dangle] appearing in mutex.rs
#![feature(dropck_eyepatch)]
// Needed to suppress errors, we inherited this from rust-sgx-sdk sgx_tstd
#![feature(auto_traits)]
// Needed because condvar and rwlock are dropping Result sometimes
#![allow(unused_must_use)]
// Needed because condvar does this
#![allow(clippy::mut_from_ref)]
// Needed because mutex drops copies all over the place
#![allow(clippy::drop_copy)]
// rwlock does this in its spinlock
#![allow(clippy::while_immutable_condition)]
// Various ::new() calls are const fn
#![feature(const_fn)]
// !Send = https://github.com/rust-lang/rust/issues/68318
#![feature(negative_impls)]

extern crate alloc;
#[cfg(feature = "sgx_panic")]
extern crate mc_sgx_panic;
extern crate mc_sgx_types;

mod condvar;
mod mutex;
mod poison;
mod rwlock;
mod spinlock;
mod thread;

pub use condvar::SgxCondvar as Condvar;
pub use mutex::{SgxMutex as Mutex, SgxMutexGuard as MutexGuard};
pub use poison::{Guard, PoisonError};
pub use rwlock::{
    SgxRwLock as RwLock, SgxRwLockReadGuard as RwLockReadGuard,
    SgxRwLockWriteGuard as RwLockWriteGuard,
};
pub use spinlock::{SgxSpinlock, SgxSpinlockGuard};
pub use thread::thread_self;
