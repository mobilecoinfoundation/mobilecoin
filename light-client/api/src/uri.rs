// Copyright (c) 2018-2023 The MobileCoin Foundation

use mc_util_uri::{Uri, UriScheme};

/// Light Client Uri Scheme
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct LightClientScheme {}

impl UriScheme for LightClientScheme {
    /// The part before the '://' of a URL.
    const SCHEME_SECURE: &'static str = "light-client";
    const SCHEME_INSECURE: &'static str = "insecure-light-client";

    /// Default port numbers
    const DEFAULT_SECURE_PORT: u16 = 443;
    const DEFAULT_INSECURE_PORT: u16 = 3223;
}

/// Uri used when talking to a Light Client service, with the right default
/// ports and scheme.
pub type LightClientUri = Uri<LightClientScheme>;
