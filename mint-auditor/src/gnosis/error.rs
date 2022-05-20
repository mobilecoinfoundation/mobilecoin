// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Data type for Gnosis-related errors.

use displaydoc::Display;
use url::ParseError;

/// Data type for Gnosis-related errors
#[derive(Debug, Display)]
pub enum Error {
    /// Url parse: {0}
    UrlParse(ParseError),

    /// Other: {0}
    Other(String),
}

impl From<ParseError> for Error {
    fn from(err: ParseError) -> Self {
        Self::UrlParse(err)
    }
}
