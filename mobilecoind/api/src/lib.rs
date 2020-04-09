// Copyright (c) 2018-2020 MobileCoin Inc.

//! mobilecoind gRPC API.

pub mod mobilecoind_api;
pub mod mobilecoind_api_grpc;

pub mod empty {
    pub use protobuf::well_known_types::Empty;
}

pub use crate::{conversions::ConversionError, mobilecoind_api::*};
pub use mobilecoin_api::external;
pub use protobuf::well_known_types::Empty;

pub mod conversions;
