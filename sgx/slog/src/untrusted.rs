// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::common::EnclaveLogMessage;
use prost::Message;
use slog;
use slog_scope;
use std;

static ENCLAVE_SLOG_LOCATION: slog::RecordLocation = slog::RecordLocation {
    file: "<enclave>",
    line: 0,
    column: 0,
    function: "",
    module: "<enclave>",
};

/// # Safety
///
/// This function is marked unsafe due to receiving a raw pointer from the caller.
#[no_mangle]
pub unsafe extern "C" fn enclave_log(msg: *const u8, msg_len: usize) {
    let msg_bytes = std::slice::from_raw_parts(msg, msg_len);
    let msg = EnclaveLogMessage::decode(msg_bytes);

    match msg {
        Ok(msg) => {
            let mut logger = slog_scope::logger().new(slog::o!(
                "module" => msg.module,
                "src" => format!("{}:{}", msg.file, msg.line),
            ));
            for (k, v) in msg.key_values.iter() {
                logger = logger.new(slog::o!(k.clone() => v.clone()));
            }

            let record_static = slog::RecordStatic {
                location: &ENCLAVE_SLOG_LOCATION,
                tag: &msg.tag,
                level: slog::Level::from_usize(msg.level as usize).unwrap_or(slog::Level::Critical),
            };

            logger.log(&slog::Record::new(
                &record_static,
                &format_args!("{}", msg.message),
                slog::b!(),
            ));
        }
        Err(e) => eprintln!(
            "Enclave log message contained invalid message:\n{}\n{:?}",
            e, msg_bytes
        ),
    }
}
