// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Backend which forwards EnclaveLogMessages to slog with appropriate source
//! information

use mc_common::logger::{
    global_log, slog,
    slog::{Level, Record, RecordLocation, RecordStatic},
    slog_scope,
};
use mc_sgx_slog::EnclaveLogMessage;
use prost::Message;
use std::slice;

static ENCLAVE_SLOG_LOCATION: RecordLocation = RecordLocation {
    file: "<enclave>",
    line: 0,
    column: 0,
    function: "",
    module: "<enclave>",
};

// This function is unsafe, if the caller misuses the API it can cause undefined behavior
#[no_mangle]
pub unsafe extern "C" fn enclave_log(msg: *const u8, msg_len: usize) {
    enclave_log_impl(slice::from_raw_parts(msg, msg_len));
}

fn enclave_log_impl(msg_bytes: &[u8]) {
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

            let record_static = RecordStatic {
                location: &ENCLAVE_SLOG_LOCATION,
                tag: &msg.tag,
                level: Level::from_usize(msg.level as usize).unwrap_or(Level::Critical),
            };

            logger.log(&Record::new(
                &record_static,
                &format_args!("{}", msg.message),
                slog::b!(),
            ));
        }
        Err(e) => global_log::error!(
            "Enclave log message contained invalid message:\n{}\n{:?}",
            e,
            msg_bytes
        ),
    }
}
