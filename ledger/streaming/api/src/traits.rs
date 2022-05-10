// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::Result;
use futures::{Future, Stream};

/// A source for streams of elements of the given type.
pub trait Streamer<Element, Request> {
    /// The specific type of stream.
    type Stream<'s>: Stream<Item = Element> + 's
    where
        Self: 's;

    /// Start streaming elements.
    /// starting_height is a hint to the stream impl for where to start:
    /// the returned stream may start later this height, but no earlier.
    fn get_stream(&self, request: Request) -> Result<Self::Stream<'_>>;
}

/// A helper that can fetch elements on demand.
pub trait Fetcher<Element, SingleRequest, MultipleRequest> {
    /// Future for fetching single elements.
    type Single<'s>: Future<Output = Element> + 's
    where
        Self: 's;
    /// Stream for fetching multiple elements.
    type Multiple<'s>: Stream<Item = Element> + 's
    where
        Self: 's;

    /// Fetch a single element matching the given request.
    fn fetch_single(&self, request: SingleRequest) -> Self::Single<'_>;

    /// Fetch multiple elements, corresponding to the given range.
    fn fetch_multiple(&self, request: MultipleRequest) -> Self::Multiple<'_>;
}
