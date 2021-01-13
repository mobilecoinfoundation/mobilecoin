// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Code that is common to both enclave and untrusted.

use mc_common::logger::slog;
use slog::KV;

use alloc::string::{String, ToString};
use prost::Message;

#[derive(Message)]
pub struct EnclaveLogMessage {
    #[prost(string, tag = "1")]
    pub message: String,

    #[prost(string, tag = "2")]
    pub file: String,

    #[prost(uint32, tag = "3")]
    pub line: u32,

    #[prost(string, tag = "4")]
    pub module: String,

    #[prost(string, tag = "5")]
    pub tag: String,

    #[prost(uint64, tag = "6")]
    pub level: u64,

    #[prost(btree_map = "string, string", tag = "7")]
    pub key_values: ::alloc::collections::BTreeMap<String, String>,
}

impl EnclaveLogMessage {
    // This is only used inside the enclace, so when building this for untrusted, we get an used
    // warning.
    #[allow(dead_code)]
    pub fn new(record: &slog::Record, values: &slog::OwnedKVList) -> Self {
        let mut enclave_log_message = Self {
            message: record.msg().to_string(),
            file: record.location().file.to_string(),
            line: record.location().line,
            module: record.location().module.to_string(),
            tag: record.tag().to_string(),
            level: record.level().as_usize() as u64,
            key_values: Default::default(),
        };

        // Errors ignored as enclave logging is "best effort" but if it fails there isn't anything
        // useful to do.
        let _ = record.kv().serialize(record, &mut enclave_log_message);
        let _ = values.serialize(record, &mut enclave_log_message);

        enclave_log_message
    }
}

impl slog::Serializer for EnclaveLogMessage {
    fn emit_arguments(&mut self, key: slog::Key, val: &core::fmt::Arguments) -> slog::Result {
        self.key_values.insert(key.into(), val.to_string());
        Ok(())
    }
}
