// Copyright (c) 2018-2021 The MobileCoin Foundation

//! MobileCoin Logging.
//!
//! The configuration of our logging is affected by environment variables. The
//! following variables are relevant:
//! - MC_LOG - Specifies the logging level (see
//! https://docs.rs/slog-envlogger/2.1.0/slog_envlogger/ for format)
//! - MC_LOG_GELF - When set to host:port, enables logging into a
//! [GELF](https://docs.graylog.org/en/3.0/pages/gelf.html) UDP receiver. Suitable for use with
//! [logstash](https://www.elastic.co/products/logstash).
//! - MC_LOG_UDP_JSON - When set to host:port, enables logging JSON log messages
//!   into a UDP socket.
//! Suitable for use with [filebeat](https://www.elastic.co/products/beats/filebeat).
//! - MC_LOG_EXTRA_CONTEXT - Adds an extra logging context (key=val, separated
//!   by comma).

/// Expose the standard crit! debug! error! etc macros from slog
/// (those are the ones that accept a Logger instance)
pub mod log {
    pub use slog::{crit, debug, error, info, trace, warn};
}

/// Expose slog and select useful primitives.
pub use slog;
pub use slog::{o, FnValue, Logger, PushFnValue};

/// Create a logger that discards everything.
pub fn create_null_logger() -> Logger {
    Logger::root(slog::Discard, o!())
}

cfg_if::cfg_if! {
    if #[cfg(feature = "log")] {
        /// Wrap calls to assert! macros to record an error message before panic
        #[macro_export]
        macro_rules! log_assert {
            ($logger:expr, $cond:expr) => ({
                if !$cond {
                    let cond_str = stringify!($cond);
                    log::crit!($logger, "assert!({}) failed", cond_str);
                    std::thread::sleep(Duration::from_millis(500));
                    panic!("assert!({}) failed", cond_str);
                }
            });
            ($logger:expr, $cond:expr,) => ({
                if !$cond {
                    let cond_str = stringify!($cond);
                    log::crit!($logger, "assert!({}) failed", cond_str);
                    std::thread::sleep(Duration::from_millis(500));
                    panic!("assert!({}) failed", cond_str);
                }
            });
            ($logger:expr, $cond:expr, $($arg:tt)+) => ({
                if !$cond {
                    let m = format!($($arg)+);
                    let cond_str = stringify!($cond);
                    log::crit!($logger, "assert!({}) failed, {}", cond_str, m);
                    std::thread::sleep(Duration::from_millis(500));
                    panic!("assert!({}) failed, {}", cond_str, m);
                }
            })
        }

        /// Wrap calls to assert_eq! macros to record an error message before panic
        #[macro_export]
        macro_rules! log_assert_eq {
            ($logger:expr, $left:expr, $right:expr) => ({
                log_assert!($logger, ($left) == ($right));
            });
            ($logger:expr, $left:expr, $right:expr,) => ({
                log_assert!($logger, ($left) == ($right));
            });
            ($logger:expr, $left:expr, $right:expr, $($arg:tt)+) => ({
                let m = format!($($arg)+);
                log_assert!($logger, ($left) == ($right), "{}", m);
            })
        }

        /// Wrap calls to assert_ne! macros to record an error message before panic
        #[macro_export]
        macro_rules! log_assert_ne {
            ($logger:expr, $left:expr, $right:expr) => ({
                log_assert!($logger, ($left) != ($right));
            });
            ($logger:expr, $left:expr, $right:expr,) => ({
                log_assert!($logger, ($left) != ($right));
            });
            ($logger:expr, $left:expr, $right:expr, $($arg:tt)+) => ({
                let m = format!($($arg)+);
                log_assert!($logger, ($left) != ($right), "{}", m);
            })
        }

        /// A global logger, for when passing a Logger instance is impractical.
        pub mod global_log {
            pub use slog_scope::{crit, debug, error, info, trace, warn};
        }

        /// Expose slog_scope
        pub use slog_scope;

        /// Get the global Logger instance, managed by `slog_scope`.
        #[cfg(feature = "log")]
        pub fn global_logger() -> Logger {
            slog_scope::logger()
        }

        /// Convenience wrapper around `slog_scope::scope`.
        #[cfg(feature = "log")]
        pub fn scoped_global_logger<F, R>(logger: &Logger, f: F) -> R
        where
            F: FnOnce(&Logger) -> R,
        {
            slog_scope::scope(&logger, || f(&logger))
        }
    }
}

cfg_if::cfg_if! {
    // Time tracing - only available when std is enable, since no_std has no concept of time.
    if #[cfg(all(feature = "log", feature="std"))] {
        use std::time::Instant;

        /// Simple time measurement utility, based on the [measure_time](https://docs.rs/measure_time/) crate.
        /// Note that even though the macro lives inside the `logger` module, it needs to be imported by
        /// `use mc_common::trace_time`, since Rust exports all macros at the crate level :/
        #[macro_export]
        macro_rules! trace_time {
            ($logger:expr, $($arg:tt)+) => (
                let _trace_time = $crate::logger::TraceTime::new($logger.clone(), $crate::logger::slog::record_static!($crate::logger::slog::Level::Trace, ""), format!($($arg)+));
            )
        }

        pub struct TraceTime<'a> {
            logger: Logger,
            rstatic: slog::RecordStatic<'a>,
            msg: String,
            start: Instant,
        }

        impl<'a> TraceTime<'a> {
            pub fn new(logger: Logger, rstatic: slog::RecordStatic<'a>, msg: String) -> Self {
                let start = Instant::now();
                Self {
                    logger,
                    rstatic,
                    msg,
                    start,
                }
            }
        }

        impl<'a> Drop for TraceTime<'a> {
            fn drop(&mut self) {
                let time_in_ms = (self.start.elapsed().as_secs() as f64 * 1_000.0)
                    + (self.start.elapsed().subsec_nanos() as f64 / 1_000_000.0);

                let time = match time_in_ms as u64 {
                    0..=3000 => format!("{}ms", time_in_ms),
                    3001..=60000 => format!("{:.2}s", time_in_ms / 1000.0),
                    _ => format!("{:.2}m", time_in_ms / 1000.0 / 60.0),
                };

                self.logger.log(&slog::Record::new(
                    &self.rstatic,
                    &format_args!("{}: took {}", self.msg, time),
                    slog::b!("duration_ms" => time_in_ms),
                ));
            }
        }

        #[cfg(test)]
        mod trace_time_tests {
            use super::*;

            #[test]
            fn basic_trace_time() {
                let logger = create_test_logger("basic_trace_time".to_string());

                slog_scope::scope(&logger.clone(), || {
                    trace_time!(global_logger(), "test global");

                    {
                        trace_time!(logger, "test inner");
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }

                    std::thread::sleep(std::time::Duration::from_millis(10));
                });
            }
        }
    }
}

cfg_if::cfg_if! {
    // Loggers
    if #[cfg(all(feature = "log", feature = "loggers"))] {
        mod loggers;
        pub use loggers::*;
    }
}
