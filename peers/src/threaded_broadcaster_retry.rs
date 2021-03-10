// Copyright (c) 2018-2021 The MobileCoin Foundation

use retry::delay::Fibonacci;
use std::time::{Duration, Instant};

/// Default number of attempts to make at delivering each message.
pub const DEFAULT_RETRY_MAX_ATTEMPTS: usize = 3;

/// Initial delay duration when attempting to retry calls.
pub const DEFAULT_RETRY_INITIAL_DELAY: Duration = Duration::from_secs(1);

/// Maximal message age before we do not attempt to deliver it.
pub const DEFAULT_MAX_MESSAGE_AGE: Duration = Duration::from_secs(30);

/// An abstraction of retry parameters used by `ThreadedBroadcaster`.
pub trait RetryPolicy: Clone + Send + 'static {
    /// Return an iterator to be used by `retry::retry()`.
    fn get_delay_iterator(&self) -> Box<dyn Iterator<Item = Duration>>;

    /// Maximal message age to broadcast.
    fn get_max_message_age(&self) -> Duration;
}

/// A simple retry policy, where each retry uses a delay that is the sum of the
/// two previous delays.
#[derive(Clone)]
pub struct FibonacciRetryPolicy {
    /// Initial value for the Fibonacci series.
    initial_delay: Duration,

    /// Maxmimal number of attempts to perform.
    max_attempts: usize,

    /// Maximal message age to process (messages older than this would get
    /// dropped).
    max_message_age: Duration,
}
impl Default for FibonacciRetryPolicy {
    fn default() -> Self {
        Self {
            initial_delay: DEFAULT_RETRY_INITIAL_DELAY,
            max_attempts: DEFAULT_RETRY_MAX_ATTEMPTS,
            max_message_age: DEFAULT_MAX_MESSAGE_AGE,
        }
    }
}
impl RetryPolicy for FibonacciRetryPolicy {
    fn get_delay_iterator(&self) -> Box<dyn Iterator<Item = Duration>> {
        Box::new(
            Fibonacci::from_millis(self.initial_delay.as_millis() as u64)
                // The `retry` crate does not touch the delay iterator for it's first attempt,
                // so if we want to have `max_attempts` attempts we need the iterator to return
                // that number minus one.
                .take(self.max_attempts - 1),
        )
    }

    fn get_max_message_age(&self) -> Duration {
        self.max_message_age
    }
}
impl FibonacciRetryPolicy {
    pub fn max_attempts(&mut self, val: usize) -> &mut Self {
        self.max_attempts = val;
        self
    }

    pub fn initial_delay(&mut self, val: Duration) -> &mut Self {
        self.initial_delay = val;
        self
    }

    pub fn max_message_age(&mut self, val: Duration) -> &mut Self {
        self.max_message_age = val;
        self
    }
}

/// An `Iterator` extension that adds the `.with_deadline()` method,
/// forcing the `Iterator` to to terminate if a given deadline is exceeded.
pub struct WithDeadline<I> {
    pub iter: I,
    pub deadline: Instant,
}

impl<I> WithDeadline<I> {
    pub fn new(iter: I, deadline: Instant) -> Self {
        Self { iter, deadline }
    }
}

impl<I> Iterator for WithDeadline<I>
where
    I: Iterator,
{
    type Item = <I as Iterator>::Item;

    #[inline]
    fn next(&mut self) -> Option<<I as Iterator>::Item> {
        if Instant::now() < self.deadline {
            self.iter.next()
        } else {
            None
        }
    }
}

pub trait IteratorWithDeadlineExt: Iterator {
    fn with_deadline(self, deadline: std::time::Instant) -> WithDeadline<Self>
    where
        Self: Sized,
    {
        WithDeadline::new(self, deadline)
    }
}

impl<I: Iterator> IteratorWithDeadlineExt for I {}
