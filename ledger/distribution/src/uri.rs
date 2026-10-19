// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! Distribution target URI

use displaydoc::Display;
use std::{path::PathBuf, str::FromStr};
use url::Url;

/// Canonicalize a region using Rusoto 0.48's accepted names and aliases.
pub(crate) fn canonical_region(region: &str) -> Option<&'static str> {
    match region.to_lowercase().as_str() {
        "ap-east-1" | "apeast1" => Some("ap-east-1"),
        "ap-northeast-1" | "apnortheast1" => Some("ap-northeast-1"),
        "ap-northeast-2" | "apnortheast2" => Some("ap-northeast-2"),
        "ap-northeast-3" | "apnortheast3" => Some("ap-northeast-3"),
        "ap-south-1" | "apsouth1" => Some("ap-south-1"),
        "ap-southeast-1" | "apsoutheast1" => Some("ap-southeast-1"),
        "ap-southeast-2" | "apsoutheast2" => Some("ap-southeast-2"),
        "ap-southeast-3" | "apsoutheast3" => Some("ap-southeast-3"),
        "ca-central-1" | "cacentral1" => Some("ca-central-1"),
        "eu-central-1" | "eucentral1" => Some("eu-central-1"),
        "eu-west-1" | "euwest1" => Some("eu-west-1"),
        "eu-west-2" | "euwest2" => Some("eu-west-2"),
        "eu-west-3" | "euwest3" => Some("eu-west-3"),
        "eu-north-1" | "eunorth1" => Some("eu-north-1"),
        "eu-south-1" | "eusouth1" => Some("eu-south-1"),
        "me-south-1" | "mesouth1" => Some("me-south-1"),
        "sa-east-1" | "saeast1" => Some("sa-east-1"),
        "us-east-1" | "useast1" => Some("us-east-1"),
        "us-east-2" | "useast2" => Some("us-east-2"),
        "us-west-1" | "uswest1" => Some("us-west-1"),
        "us-west-2" | "uswest2" => Some("us-west-2"),
        "us-gov-east-1" | "usgoveast1" => Some("us-gov-east-1"),
        "us-gov-west-1" | "usgovwest1" => Some("us-gov-west-1"),
        "cn-north-1" | "cnnorth1" => Some("cn-north-1"),
        "cn-northwest-1" | "cnnorthwest1" => Some("cn-northwest-1"),
        "af-south-1" | "afsouth1" => Some("af-south-1"),
        _ => None,
    }
}

/// Destinations for distribution.
#[derive(Clone, Debug)]
pub enum Destination {
    /// Write to S3.
    S3 {
        /// Optional AWS region override from the URI.
        region: Option<String>,
        /// S3 bucket name.
        bucket: String,
        /// Object key prefix within the bucket.
        prefix: PathBuf,
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

    /// Invalid S3 region: Not a valid AWS region: {0}
    InvalidS3Region(String),
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
                    .map(|value| {
                        canonical_region(&value)
                            .map(str::to_owned)
                            .ok_or_else(|| UriParseError::InvalidS3Region(value.to_lowercase()))
                    })
                    .transpose()?;

                let (bucket, prefix) = path.split_once('/').unwrap_or((&path, ""));
                Destination::S3 {
                    bucket: bucket.to_owned(),
                    prefix: PathBuf::from(prefix),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_destinations() {
        for (uri, expected_bucket, expected_prefix) in [
            ("s3://bucket", "bucket", ""),
            ("s3://bucket/", "bucket", ""),
            (
                "s3://bucket/node.example/nested/",
                "bucket",
                "node.example/nested",
            ),
        ] {
            let destination = uri.parse::<Uri>().unwrap().destination;
            let Destination::S3 { bucket, prefix, .. } = destination else {
                panic!("expected S3")
            };
            assert_eq!(bucket, expected_bucket);
            assert_eq!(prefix, PathBuf::from(expected_prefix));
        }
    }

    #[test]
    fn local_destination_and_invalid_uris() {
        let destination = "file:///tmp/ledger/".parse::<Uri>().unwrap().destination;
        assert!(
            matches!(destination, Destination::Local { path } if path.as_path() == std::path::Path::new("/tmp/ledger"))
        );
        assert!(matches!(
            "https://bucket/prefix".parse::<Uri>(),
            Err(UriParseError::UnknownScheme(_))
        ));
        assert!("s3://".parse::<Uri>().is_err());
    }

    #[test]
    fn legacy_region_names_and_aliases() {
        // The full region set accepted by Rusoto 0.48.
        for expected in [
            "ap-east-1",
            "ap-northeast-1",
            "ap-northeast-2",
            "ap-northeast-3",
            "ap-south-1",
            "ap-southeast-1",
            "ap-southeast-2",
            "ap-southeast-3",
            "ca-central-1",
            "eu-central-1",
            "eu-west-1",
            "eu-west-2",
            "eu-west-3",
            "eu-north-1",
            "eu-south-1",
            "me-south-1",
            "sa-east-1",
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "us-gov-east-1",
            "us-gov-west-1",
            "cn-north-1",
            "cn-northwest-1",
            "af-south-1",
        ] {
            for value in [
                expected.to_owned(),
                expected.to_uppercase(),
                expected.replace('-', ""),
                expected.replace('-', "").to_uppercase(),
            ] {
                let uri = format!("s3://bucket/prefix?region={value}");
                let Destination::S3 { region, .. } = uri.parse::<Uri>().unwrap().destination else {
                    panic!("expected S3");
                };
                assert_eq!(region.as_deref(), Some(expected), "{value}");
            }
        }
    }

    #[test]
    fn invalid_explicit_regions_are_rejected() {
        for value in [
            "unknown",
            "eu-west-99",
            "ap-southeast-4",
            "%20eu-west-2",
            "eu-west-2%20",
            "%20",
            "eu--west-2",
        ] {
            assert!(matches!(
                format!("s3://bucket/prefix?region={value}").parse::<Uri>(),
                Err(UriParseError::InvalidS3Region(_))
            ));
        }
    }

    #[test]
    fn empty_explicit_region_is_ignored() {
        let destination = "s3://bucket/prefix?region="
            .parse::<Uri>()
            .unwrap()
            .destination;
        assert!(matches!(destination, Destination::S3 { region: None, .. }));
    }

    #[test]
    fn first_nonempty_region_parameter_wins() {
        for (query, expected) in [
            ("?region=&region=EuWeSt2", "eu-west-2"),
            ("?region=USEAST1&region=unknown", "us-east-1"),
        ] {
            let Destination::S3 { region, .. } = format!("s3://bucket/prefix{query}")
                .parse::<Uri>()
                .unwrap()
                .destination
            else {
                panic!("expected S3");
            };
            assert_eq!(region.as_deref(), Some(expected));
        }
    }
}
