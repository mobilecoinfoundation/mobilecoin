// Copyright (c) 2018-2020 MobileCoin Inc.

use prost::Message;

// This is the ocall for passing the message buffer to the untrusted code
// See sgx_slog.edl
extern "C" {
    fn enclave_log(msg: *const u8, msg_len: usize);
}

/// Expose slog
pub use slog::*;

/// Expose the standard crit! debug! error! etc macros from slog
/// (those are the ones that accept a Logger instance), under the `log` namespace.
pub mod log {
    pub use slog::{crit, debug, error, info, trace, warn};
}

/// slog Drain for use inside enclaves, that uses an OCALL to output log messages.
pub struct EnclaveOCallDrain;
impl slog::Drain for EnclaveOCallDrain {
    type Ok = ();
    type Err = ();

    fn log(
        &self,
        record: &slog::Record,
        values: &slog::OwnedKVList,
    ) -> core::result::Result<Self::Ok, Self::Err> {
        let msg = crate::common::EnclaveLogMessage::new(record, values);

        let mut serialized_msg = alloc::vec::Vec::new();
        if msg.encode(&mut serialized_msg).is_ok() {
            unsafe { enclave_log(serialized_msg.as_ptr(), serialized_msg.len()) };
            Ok(())
        } else {
            Err(())
        }
    }
}

/// Utility method to create a Logger suitable for in-enclave logging.
#[cfg(debug_assertions)]
pub fn default_logger() -> Logger {
    Logger::root(slog::Fuse(EnclaveOCallDrain {}), o!())
}

// No logs from enclave when not compiled in debug mode.
#[cfg(not(debug_assertions))]
pub fn default_logger() -> Logger {
    Logger::root(slog::Fuse(slog::Discard), o!())
}
