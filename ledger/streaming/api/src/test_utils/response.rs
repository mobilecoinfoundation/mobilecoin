// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Response helper.

use super::make_components;
use crate::{make_subscribe_response, streaming_blocks::SubscribeResponse, Error, Result};
use grpcio::WriteFlags;
use mc_crypto_keys::Ed25519Pair;

/// Generate the requested number of [Responses], signed with the given signer.
pub fn make_responses(num_responses: usize, signer: &Ed25519Pair) -> Responses {
    make_components(num_responses)
        .into_iter()
        .map(|components| make_subscribe_response(&components, signer).into())
        .collect()
}

/// Helper for a hard-coded [Result<SubscribeResponse>].
#[derive(Clone, Debug)]
pub struct Response(pub Result<SubscribeResponse>);

/// Helper for a list of [Response]s.
pub type Responses = Vec<Response>;

impl Response {
    /// Maps this [Response] to a tuple with the given [WriteFlags]
    pub fn with_write_flags(
        self,
        flags: WriteFlags,
    ) -> grpcio::Result<(SubscribeResponse, WriteFlags)> {
        grpcio::Result::<SubscribeResponse>::from(self).map(|r| (r, flags))
    }
}

impl AsRef<Result<SubscribeResponse>> for Response {
    fn as_ref(&self) -> &Result<SubscribeResponse> {
        &self.0
    }
}

impl From<SubscribeResponse> for Response {
    fn from(src: SubscribeResponse) -> Self {
        Self(Ok(src))
    }
}

impl From<Error> for Response {
    fn from(src: Error) -> Self {
        Self(Err(src))
    }
}

impl From<Result<SubscribeResponse>> for Response {
    fn from(src: Result<SubscribeResponse>) -> Self {
        Self(src)
    }
}

impl From<Response> for grpcio::Result<SubscribeResponse> {
    fn from(src: Response) -> grpcio::Result<SubscribeResponse> {
        src.0.map_err(|err| grpcio::Error::Codec(err.into()))
    }
}
