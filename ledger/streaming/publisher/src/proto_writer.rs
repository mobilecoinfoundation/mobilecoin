// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Define a trait for writing protobufs.

use futures::Future;
use mc_ledger_streaming_api::Result;
use protobuf::Message;
use std::{fmt::Debug, path::Path};

/// Trait that abstracts the functionality of writing a protobuf.
pub trait ProtoWriter: Clone + Debug {
    /// Upload the given [Message] to the given path.
    fn upload<'up, M: Message>(&'up self, proto: &'up M, dest: &'up Path) -> Self::Future<'up>;

    /// Type alias for the [Future] returned by `upload()`.
    type Future<'u>: Future<Output = Result<()>> + 'u
    where
        Self: 'u;
}
