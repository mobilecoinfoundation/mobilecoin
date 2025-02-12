// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::traits::{ConnectionUri, UriScheme};
use displaydoc::Display;
use mc_common::ResponderId;
use percent_encoding::percent_decode_str;
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    marker::PhantomData,
    str::FromStr,
};
use url::Url;

/// Error type for URI parsing.
#[derive(Clone, Eq, PartialEq, Debug, Display)]
pub enum UriParseError {
    /// Url parse error: "{0}", "{1}"
    UrlParse(String, url::ParseError),
    /// Missing host
    MissingHost,
    /// Unknown scheme: Valid possibilities are `{0}`, `{1}`
    UnknownScheme(&'static str, &'static str),
    /// Percent decoding error: '{0}'
    PercentDecoding(String),
}

impl std::error::Error for UriParseError {}

/// Represents a URI with custom scheme validation and other helpers.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Uri<Scheme: UriScheme> {
    /// The original Url object used to construct this object.
    url: Url,

    /// Hostname.
    host: String,

    /// Consensus port.
    port: u16,

    /// Whether to use TLS when connecting.
    use_tls: bool,

    /// Optional username.
    username: String,

    /// Optional password.
    password: String,

    /// The uri scheme
    _scheme: PhantomData<Scheme>,
}

impl<Scheme: UriScheme> Uri<Scheme> {
    /// Change the port number of this URI.
    pub fn set_port(&mut self, port: u16) {
        self.url
            .set_port(Some(port))
            .expect("should never fail on valid url");
        self.port = port;
    }

    /// Extract the subdomain from url
    pub fn subdomain(&self) -> Option<&str> {
        let host_str = self.url.host_str()?;
        host_str.split_once('.').map(|(first, _)| first)
    }
}

impl<Scheme: UriScheme> ConnectionUri for Uri<Scheme> {
    fn url(&self) -> &Url {
        &self.url
    }

    fn host(&self) -> String {
        self.host.clone()
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    fn use_tls(&self) -> bool {
        self.use_tls
    }

    fn username(&self) -> String {
        self.username.clone()
    }

    fn password(&self) -> String {
        self.password.clone()
    }
}

impl<Scheme: UriScheme> Uri<Scheme> {
    /// Creates a `Uri` from a `ResponderId`
    pub fn try_from_responder_id(
        responder_id: ResponderId,
        use_tls: bool,
    ) -> Result<Self, UriParseError> {
        let scheme = match use_tls {
            true => Scheme::SCHEME_SECURE,
            false => Scheme::SCHEME_INSECURE,
        };
        let uri_string = format!("{scheme}://{responder_id}");

        Self::from_str(&uri_string)
    }
}

impl<Scheme: UriScheme> Display for Uri<Scheme> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let scheme = if self.use_tls {
            Scheme::SCHEME_SECURE
        } else {
            Scheme::SCHEME_INSECURE
        };
        write!(f, "{}://{}:{}/", scheme, self.host, self.port)
    }
}

impl<Scheme: UriScheme> FromStr for Uri<Scheme> {
    type Err = UriParseError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let mut url =
            Url::parse(src).map_err(|err| UriParseError::UrlParse(src.to_string(), err))?;

        if Scheme::NORMALIZE_PATH_TRAILING_SLASH && !url.path().ends_with('/') {
            url.set_path(&format!("{}/", url.path()));
        }

        let host = url
            .host_str()
            .ok_or(UriParseError::MissingHost)?
            .to_string();
        if host.is_empty() {
            return Err(UriParseError::MissingHost);
        }

        let use_tls = if url.scheme() == Scheme::SCHEME_SECURE {
            true
        } else if url.scheme() == Scheme::SCHEME_INSECURE {
            false
        } else {
            return Err(UriParseError::UnknownScheme(
                Scheme::SCHEME_SECURE,
                Scheme::SCHEME_INSECURE,
            ));
        };

        let port = match (url.port(), use_tls) {
            (Some(port), _) => port,
            (None, true) => Scheme::DEFAULT_SECURE_PORT,
            (None, false) => Scheme::DEFAULT_INSECURE_PORT,
        };

        let username_percent_encoded = url.username().to_owned();
        let username = percent_decode_str(&username_percent_encoded)
            .decode_utf8()
            .map_err(|_| UriParseError::PercentDecoding(username_percent_encoded.clone()))?
            .to_string();

        let password_percent_encoded = url
            .password()
            .map(|s| s.to_owned())
            .unwrap_or_else(|| "".to_owned());
        let password = percent_decode_str(&password_percent_encoded)
            .decode_utf8()
            .map_err(|_| UriParseError::PercentDecoding(password_percent_encoded.clone()))?
            .to_string();

        Ok(Self {
            url,
            host,
            port,
            use_tls,
            username,
            password,
            _scheme: Default::default(),
        })
    }
}

impl<Scheme: UriScheme> AsRef<str> for Uri<Scheme> {
    fn as_ref(&self) -> &str {
        self.url.as_str()
    }
}

impl<Scheme: UriScheme> serde::Serialize for Uri<Scheme> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.url.as_str())
    }
}

impl<'de, Scheme: UriScheme> serde::Deserialize<'de> for Uri<Scheme> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, Unexpected, Visitor};

        struct UriVisitor<Scheme: UriScheme> {
            pub _scheme: PhantomData<Scheme>,
        }

        impl<S: UriScheme> Visitor<'_> for UriVisitor<S> {
            type Value = Uri<S>;

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                formatter.write_str("a string representing an URL")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Uri::from_str(s).map_err(|err| {
                    Error::invalid_value(Unexpected::Str(s), &err.to_string().as_str())
                })
            }
        }

        deserializer.deserialize_str(UriVisitor::<Scheme> {
            _scheme: Default::default(),
        })
    }
}
