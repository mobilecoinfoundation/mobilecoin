// Copyright (c) 2018-2021 The MobileCoin Foundation

use core::{
    convert::TryFrom,
    fmt::{Debug, Display},
    hash::Hash,
    result::Result as StdResult,
};
use displaydoc::Display;
use ed25519::signature::Error as SignatureError;
use mc_common::{NodeID, ResponderId, ResponderIdParseError};
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Public, KeyError};
use std::{path::PathBuf, str::FromStr};
use url::Url;

#[derive(Debug, Display, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub enum UriConversionError {
    /// Error converting key: {0}
    KeyConversion(KeyError),
    /// Error with Ed25519 signature
    Signature,
    /// Error decoding base64
    Base64Decode,
    /// Error parsing ResponderId {0}, {1}
    ResponderId(String, ResponderIdParseError),
    /// No consensus-msg-key provided
    NoPubkey,
}

impl From<KeyError> for UriConversionError {
    fn from(src: KeyError) -> Self {
        UriConversionError::KeyConversion(src)
    }
}

impl From<SignatureError> for UriConversionError {
    fn from(_src: SignatureError) -> Self {
        // NOTE: ed25519::signature::Error does not implement Eq/Ord
        UriConversionError::Signature
    }
}

impl From<base64::DecodeError> for UriConversionError {
    fn from(_src: base64::DecodeError) -> Self {
        // NOTE: Base64::DecodeError does not implement Eq/Ord
        UriConversionError::Base64Decode
    }
}

impl From<ResponderIdParseError> for UriConversionError {
    fn from(src: ResponderIdParseError) -> Self {
        match src.clone() {
            ResponderIdParseError::FromUtf8Error(contents) => {
                UriConversionError::ResponderId(hex::encode(contents), src)
            }
            ResponderIdParseError::InvalidFormat(contents) => {
                UriConversionError::ResponderId(contents, src)
            }
        }
    }
}

/// A base URI trait.
pub trait ConnectionUri:
    Clone + Display + Eq + Hash + Ord + PartialEq + PartialOrd + Send + Sync
{
    /// Retrieve a reference to the underlying Url object.
    fn url(&self) -> &Url;

    /// Retreive the host part of the URI.
    fn host(&self) -> String;

    /// Retreive the port part of the URI.
    fn port(&self) -> u16;

    /// Retrieve the host:port string for this connection.
    fn addr(&self) -> String;

    /// Whether TLS should be used for this connection.
    fn use_tls(&self) -> bool;

    /// Retrieve the username part of the URI, or an empty string if one is not
    /// available.
    fn username(&self) -> String;

    /// Retrieve the password part of the URI, or an empty string if one is not
    /// available.
    fn password(&self) -> String;

    /// Retrieve the responder id for this connection.
    fn responder_id(&self) -> StdResult<ResponderId, UriConversionError> {
        let responder_id_string = self
            .get_param("responder-id")
            .unwrap_or_else(|| self.addr());
        Ok(ResponderId::from_str(&responder_id_string)?)
    }

    fn node_id(&self) -> StdResult<NodeID, UriConversionError> {
        Ok(NodeID {
            responder_id: self.responder_id()?,
            public_key: self.consensus_msg_key()?,
        })
    }

    /// Retrieve the Public Key for Message Signing for this connection.
    ///
    /// Public keys via URIs are expected to be either hex or base64 encoded,
    /// with the key algorithm specified in the URI as well, for future
    /// compatibility with different key schemes.
    // FIXME: Add key ?algo=ED25519
    fn consensus_msg_key(&self) -> StdResult<Ed25519Public, UriConversionError> {
        if let Some(pubkey) = self.get_param("consensus-msg-key") {
            match hex::decode(&pubkey) {
                Ok(pubkey_bytes) => Ok(Ed25519Public::try_from(pubkey_bytes.as_slice())?),
                Err(_e) => {
                    let pubkey_bytes = base64::decode_config(&pubkey, base64::URL_SAFE)?;
                    Ok(Ed25519Public::try_from_der(&pubkey_bytes)?)
                }
            }
        } else {
            Err(UriConversionError::NoPubkey)
        }
    }

    /// Get the value of a query parameter, if parameter is available.
    fn get_param(&self, name: &str) -> Option<String> {
        self.url().query_pairs().find_map(|(k, v)| {
            if k == name && !v.is_empty() {
                Some(v.to_string())
            } else {
                None
            }
        })
    }

    /// Get the value of a boolean query parameter.
    fn get_bool_param(&self, name: &str) -> bool {
        let p = self.get_param(name).unwrap_or_else(|| "0".into());
        p == "1" || p == "true"
    }

    /// Optional TLS hostname override.
    fn tls_hostname_override(&self) -> Option<String> {
        self.get_param("tls-hostname")
    }

    /// Retrieve the CA bundle to use for this connection. If the `ca-bundle`
    /// query parameter is present, we will error if we fail at loading a
    /// certificate. When it is not present we will make a best-effort
    /// attempt and return Ok(None) if no certificate could be loaded.
    fn ca_bundle(&self) -> StdResult<Option<Vec<u8>>, String> {
        let ca_bundle_path = self.get_param("ca-bundle").map(PathBuf::from);

        // If we haven't received a ca-bundle query parameter, we're okay with host_cert
        // not returning anything. If the ca-bundle query parameter was present
        // we will propagate errors from `read_ca_bundle`.
        ca_bundle_path.map_or_else(
            || Ok(mc_util_host_cert::read_ca_bundle(None).ok()),
            |bundle_path| mc_util_host_cert::read_ca_bundle(Some(bundle_path)).map(Some),
        )
    }

    /// Retrieve the TLS chain file path to use for this connection.
    fn tls_chain_path(&self) -> StdResult<String, String> {
        self.get_param("tls-chain")
            .ok_or_else(|| format!("Missing tls-chain query parameter for {}", self.url()))
    }

    /// Retrieve the TLS chain to use for this connection.
    fn tls_chain(&self) -> StdResult<Vec<u8>, String> {
        let path = self.tls_chain_path()?;
        std::fs::read(path.clone())
            .map_err(|e| format!("Failed reading TLS chain from {}: {:?}", path, e))
    }

    /// Retrieve the TLS key file path to use for this connection.
    fn tls_key_path(&self) -> StdResult<String, String> {
        self.get_param("tls-key")
            .ok_or_else(|| format!("Missing tls-key query parameter for {}", self.url()))
    }

    /// Retrieve the TLS key to use for this connection.
    fn tls_key(&self) -> StdResult<Vec<u8>, String> {
        let path = self.tls_key_path()?;
        std::fs::read(path.clone())
            .map_err(|e| format!("Failed reading TLS key from {}: {:?}", path, e))
    }
}

/// A trait with associated constants, representing a URI scheme and default
/// ports
pub trait UriScheme:
    Debug + Hash + Ord + PartialOrd + Eq + PartialEq + Send + Sync + Clone
{
    const SCHEME_SECURE: &'static str;
    const SCHEME_INSECURE: &'static str;
    const DEFAULT_SECURE_PORT: u16;
    const DEFAULT_INSECURE_PORT: u16;

    /// When true, ensure the path components of a URI ends with a slash.
    /// This is genenerally the desired behavior for our URIs since we currently
    /// do not use any of them to point at a specific file. Having a
    /// consistent trailing slash ensures that parsing `scheme://host` and
    /// `scheme://host/` results in equal objects.
    const NORMALIZE_PATH_TRAILING_SLASH: bool = true;
}
