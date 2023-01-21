// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

use clap::Parser;
use retry::delay;
use serde::Serialize;
use std::time::Duration;

/// An object which represents a retry policy for retriable errors for a grpc
/// connection
/// Use fibonacci back off. 24 retries starting at 100ms with a max back off of
/// 60000ms is about 10 min.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Parser, Serialize)]
pub struct GrpcRetryConfig {
    /// How many times to retry when we get retriable errors (grpc connection)
    #[clap(long, default_value = "24", env = "MC_GRPC_RETRY_COUNT")]
    pub grpc_retry_count: usize,

    /// Minimum delay to back off (milliseconds) when we get retriable errors
    /// (grpc connection)
    #[clap(long, default_value = "100", env = "MC_GRPC_RETRY_MIN_DELAY_MILLIS")]
    pub grpc_retry_min_delay_millis: u64,

    /// Maximum delay to back off (milliseconds) when we get retriable errors
    /// (grpc connection)
    #[clap(long, default_value = "60000", env = "MC_GRPC_RETRY_MAX_DELAY_MILLIS")]
    pub grpc_retry_max_delay_millis: u64,
}

impl Default for GrpcRetryConfig {
    fn default() -> Self {
        Self {
            grpc_retry_count: 24,
            grpc_retry_min_delay_millis: 100,
            grpc_retry_max_delay_millis: 60000,
        }
    }
}

impl GrpcRetryConfig {
    /// Set the max delay for a retry - We don't want to wait forever.
    pub fn set_max_delay(duration: Duration, max: u64) -> Duration {
        if duration > Duration::from_millis(max) {
            Duration::from_millis(max)
        } else {
            duration
        }
    }

    /// Get a duration iterator for use with retry crate based on this config
    pub fn get_retry_iterator(&self) -> impl Iterator<Item = Duration> + '_ {
        delay::Fibonacci::from_millis(self.grpc_retry_min_delay_millis)
            .take(self.grpc_retry_count)
            .map(|x| GrpcRetryConfig::set_max_delay(x, self.grpc_retry_max_delay_millis))
            .map(delay::jitter)
    }

    /// Retry an operation using this retry config
    pub fn retry<O, R, E, OR>(&self, operation: O) -> Result<R, retry::Error<E>>
    where
        O: FnMut() -> OR,
        OR: Into<retry::OperationResult<R, E>>,
    {
        retry::retry(self.get_retry_iterator(), operation)
    }
}
