// Copyright (c) 2018-2020 MobileCoin Inc.

#![no_std]
// Needed for a #[may_dangle] appearing in mutex.rs
#![feature(dropck_eyepatch)]
// Needed to suppress errors, we inherited this from rust-sgx-sdk sgx_tstd
#![feature(optin_builtin_traits)]
// Needed because condvar and rwlock are dropping Result sometimes
#![allow(unused_must_use)]
// Needed because condvar does this
#![allow(clippy::mut_from_ref)]
// Needed because mutex drops copies all over the place
#![allow(clippy::drop_copy)]
// rwlock does this in its spinlock
#![allow(clippy::while_immutable_condition)]
#![feature(const_fn)]
extern crate alloc;

extern crate sgx_libc_types;
extern crate sgx_types;

#[cfg(feature = "sgx_panic")]
extern crate sgx_panic;

mod condvar;
mod mutex;
mod poison;
mod rwlock;
mod spinlock;
mod thread;

pub use poison::{Guard, PoisonError};
pub use thread::thread_self;

// compat with std naming
pub use condvar::SgxCondvar as Condvar;
pub use mutex::{SgxMutex as Mutex, SgxMutexGuard as MutexGuard};
pub use rwlock::{
    SgxRwLock as RwLock, SgxRwLockReadGuard as RwLockReadGuard,
    SgxRwLockWriteGuard as RwLockWriteGuard,
};

// not a part of std actually
pub use spinlock::{SgxSpinlock, SgxSpinlockGuard};
