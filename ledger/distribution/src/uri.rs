// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! Distribution target URI

use displaydoc::Display;
use rusoto_core::{region::ParseRegionError, Region};
use std::{path::PathBuf, str::FromStr};
use url::Url;

/// Destinations for distribution.
#[derive(Clone, Debug)]
pub enum Destination {
    /// Write to S3.
    S3 {
        /// AWS Region.
        region: Region,
        /// S3 path.
        path: PathBuf,
    },
    /// Write to local disk.
    Local {
        /// Local path.
        path: PathBuf,
    },
}

/// Wrapper for URL and associated Destination.
#[derive(Clone, Debug)]
pub struct Uri {
    /// The original Url used to construct this object.
    pub url: Url,

    /// Destination for storing blocks
    pub destination: Destination,
}

/// URI parse errors.
#[derive(Debug, Display)]
pub enum UriParseError {
    /// Url parse error: {0}
    UrlParse(url::ParseError),

    /// Unknown scheme: {0}
    UnknownScheme(String),

    /// Missing path
    MissingPath,

    /// Invalid S3 region: {0}
    InvalidS3Region(ParseRegionError),
}

impl std::error::Error for UriParseError {}

impl FromStr for Uri {
    type Err = UriParseError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(src).map_err(UriParseError::UrlParse)?;

        let destination = match url.scheme() {
            "s3" => {
                let path = url[url::Position::BeforeHost..url::Position::AfterPath]
                    .trim_matches('/')
                    .to_string();
                if path.is_empty() {
                    return Err(UriParseError::MissingPath);
                }

                let region_param = url.query_pairs().find_map(|(k, v)| {
                    if k == "region" && !v.is_empty() {
                        Some(v.to_string())
                    } else {
                        None
                    }
                });

                let region = region_param
                    .map_or_else(|| Ok(Region::default()), |param| Region::from_str(&param))
                    .map_err(UriParseError::InvalidS3Region)?;

                Destination::S3 {
                    path: PathBuf::from(path),
                    region,
                }
            }

            "file" => {
                let path = url[url::Position::BeforeHost..url::Position::AfterPath]
                    .trim_end_matches('/')
                    .to_string();
                if path.is_empty() {
                    return Err(UriParseError::MissingPath);
                }

                Destination::Local {
                    path: PathBuf::from(path),
                }
            }

            _ => return Err(UriParseError::UnknownScheme(url.scheme().to_string())),
        };

        Ok(Self { url, destination })
    }
}
