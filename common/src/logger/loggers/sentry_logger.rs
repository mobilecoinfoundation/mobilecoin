// Copyright (c) 2018-2021 The MobileCoin Foundation

use slog::{o, Drain, Key, Level, Logger, Never, OwnedKVList, Record, Serializer, KV};

pub(crate) struct SentryLogger {
    inner: Logger,
}

impl Drain for SentryLogger {
    type Ok = ();
    type Err = Never;
    fn log(&self, info: &Record, values: &OwnedKVList) -> Result<(), Never> {
        if info.level() <= Level::Error {
            sentry::capture_event(event_from_record(info, values));
        }

        Drain::log(&self.inner, info, values)
    }
    fn is_enabled(&self, level: Level) -> bool {
        self.inner.is_enabled(level)
    }
}

impl SentryLogger {
    pub fn wrap(logger: Logger) -> Logger {
        let wrapped_logger = Self { inner: logger };

        Logger::root(wrapped_logger, o!())
    }
}

/// Creates an event from a given log record.
///
/// If `with_stacktrace` is set to `true` then a stacktrace is attached
/// from the current frame.
fn event_from_record(record: &Record, values: &OwnedKVList) -> sentry::protocol::Event<'static> {
    let mut event = sentry::protocol::Event {
        level: convert_log_level(record.level()),
        exception: vec![sentry::protocol::Exception {
            ty: "log".into(),
            value: Some(record.msg().to_string()),
            ..Default::default()
        }]
        .into(),
        ..Default::default()
    };

    event
        .extra
        .insert("module".to_string(), record.location().module.into());
    event.extra.insert(
        "location".to_string(),
        format!("{}:{}", record.location().file, record.location().line).into(),
    );

    let mut additional = KeyValueList(Vec::new());
    let _ = record.kv().serialize(record, &mut additional);
    let _ = values.serialize(record, &mut additional);
    for (k, v) in additional.0 {
        event.extra.insert(k.into(), v.into());
    }

    event
}

fn convert_log_level(level: Level) -> sentry::Level {
    match level {
        Level::Error | Level::Critical => sentry::Level::Error,
        Level::Warning => sentry::Level::Warning,
        Level::Info => sentry::Level::Info,
        Level::Debug | Level::Trace => sentry::Level::Debug,
    }
}

pub struct KeyValueList(pub Vec<(Key, String)>);

impl Serializer for KeyValueList {
    fn emit_arguments(&mut self, key: Key, val: &std::fmt::Arguments) -> slog::Result {
        self.0.push((key, format!("{}", val)));
        Ok(())
    }
}
