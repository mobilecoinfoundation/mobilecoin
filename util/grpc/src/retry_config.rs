use clap::Parser;
use retry::delay;
use serde::Serialize;
use std::time::Duration;

/// An object which represents a retry policy for retriable errors for a grpc
/// connection
#[derive(Copy, Clone, Debug, Eq, PartialEq, Parser, Serialize)]
pub struct GrpcRetryConfig {
    /// How many times to retry when we get retriable errors (grpc connection)
    #[clap(long, default_value = "3", env = "MC_GRPC_RETRY_COUNT")]
    pub grpc_retry_count: usize,

    /// How long to back off (milliseconds) when we get retriable errors (grpc
    /// connection)
    #[clap(long, default_value = "20", env = "MC_GRPC_RETRY_MILLIS")]
    pub grpc_retry_millis: u64,
}

impl Default for GrpcRetryConfig {
    fn default() -> Self {
        Self {
            grpc_retry_count: 3,
            grpc_retry_millis: 20,
        }
    }
}

impl GrpcRetryConfig {
    /// Get a duration iterator for use with retry crate based on this config
    pub fn get_retry_iterator(&self) -> impl Iterator<Item = Duration> {
        delay::Fixed::from_millis(self.grpc_retry_millis)
            .take(self.grpc_retry_count)
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
