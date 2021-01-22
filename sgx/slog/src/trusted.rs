// Copyright (c) 2018-2021 The MobileCoin Foundation

use prost::Message;

// This is the ocall for passing the message buffer to the untrusted code
// See sgx_slog.edl
extern "C" {
    fn enclave_log(msg: *const u8, msg_len: usize);
}

use mc_common::logger::slog;
use slog::{o, Logger};

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
#[cfg(feature = "ias-dev")]
pub fn default_logger() -> Logger {
    Logger::root(slog::Fuse(EnclaveOCallDrain {}), o!())
}

// No logs from enclave when not compiled in development mode.
#[cfg(not(feature = "ias-dev"))]
pub fn default_logger() -> Logger {
    Logger::root(slog::Fuse(slog::Discard), o!())
}
