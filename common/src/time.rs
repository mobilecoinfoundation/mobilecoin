// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Utilities for handling time.

use alloc::{boxed::Box, sync::Arc};
use core::{fmt::Debug, time::Duration};

/// Abstraction for getting the current time.
pub trait TimeProvider: Sync + Send {
    /// Error type
    type Error: Clone + Debug;

    /// Get the duration of time passed since the unix epoch.
    fn since_epoch(&self) -> Result<Duration, Self::Error>;
}

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use std::{
            time::{SystemTime, SystemTimeError},
            sync::Mutex,
        };

        /// An implementation of TimeProvider that relies on Rust's builtin `SystemTime`.
        #[derive(Clone, Debug, Default)]
        pub struct SystemTimeProvider;

        impl TimeProvider for SystemTimeProvider {
            type Error = SystemTimeError;

            fn since_epoch(&self) -> Result<Duration, Self::Error> {
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            }
        }

        /// A mock time provider that always returns the same value.
        #[derive(Clone, Debug)]
        pub struct MockTimeProvider {
            cur_since_epoch: Arc<Mutex<Duration>>,
        }

        impl Default for MockTimeProvider {
            fn default() -> Self {
                Self {
                    cur_since_epoch: Arc::new(Mutex::new(
                        SystemTimeProvider::default()
                            .since_epoch()
                            .expect("failed getting initial value for cur_since_epoch"),
                    )),
                }
            }
        }

        impl TimeProvider for MockTimeProvider {
            type Error = ();

            fn since_epoch(&self) -> Result<Duration, Self::Error> {
                Ok(*self.cur_since_epoch.lock().expect("mutex poisoned"))
            }
        }

        impl MockTimeProvider {
            /// Set a value for the next from_epoch call
            pub fn set_cur_since_epoch(&self, new_cur_since_epoch: Duration) {
                let mut inner = self.cur_since_epoch.lock().expect("mutex poisoned");
                *inner = new_cur_since_epoch;
            }
        }
    }
}

// Blanket implementations

impl<TP: TimeProvider> TimeProvider for Arc<TP> {
    type Error = TP::Error;

    fn since_epoch(&self) -> Result<Duration, Self::Error> {
        (**self).since_epoch()
    }
}

impl<TP: TimeProvider> TimeProvider for Box<TP> {
    type Error = TP::Error;

    fn since_epoch(&self) -> Result<Duration, Self::Error> {
        (**self).since_epoch()
    }
}
