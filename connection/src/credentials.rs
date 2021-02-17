// Copyright (c) 2018-2021 The MobileCoin Foundation

//! GRPC credentials support

use grpcio::{Error as GrpcError, RpcStatusCode};
use mc_common::time::{SystemTimeProvider, TimeProvider};
use mc_util_grpc::{BasicCredentials, TokenBasicCredentialsGenerator};
use mc_util_uri::ConnectionUri;
use std::fmt::{Debug, Display};

/// A trait that lets us determine if an error relates to authentication failure.
pub trait AuthenticationError {
    fn is_unauthenticated(&self) -> bool;
}

impl AuthenticationError for GrpcError {
    fn is_unauthenticated(&self) -> bool {
        match self {
            GrpcError::RpcFailure(rpc_status) => {
                rpc_status.status == RpcStatusCode::UNAUTHENTICATED
            }
            _ => false,
        }
    }
}

/// Error relating to credential providing.
pub trait CredentialsProviderError: Debug + Display + Send + Sync {}
impl<T> CredentialsProviderError for T where T: Debug + Display + Send + Sync {}

/// An interface for providing credentials for a given URI.
pub trait CredentialsProvider: Send + Sync {
    /// Get credentials to be used for a GRPC call.
    fn get_credentials(
        &self,
    ) -> Result<Option<BasicCredentials>, Box<dyn CredentialsProviderError + 'static>>;

    /// Clear any cached credentials so that new ones can be generated.
    /// The default implementation is a no-op.
    fn clear(&self) {}
}

/// A credentials provider that has hardcoded user/password credentials.
#[derive(Default)]
pub struct HardcodedCredentialsProvider {
    creds: Option<BasicCredentials>,
}

impl HardcodedCredentialsProvider {
    pub fn new(username: impl AsRef<str>, password: impl AsRef<str>) -> Self {
        Self {
            creds: Some(BasicCredentials::new(username.as_ref(), password.as_ref())),
        }
    }
}

impl<URI: ConnectionUri> From<&URI> for HardcodedCredentialsProvider {
    fn from(src: &URI) -> Self {
        Self::new(&src.username(), &src.password())
    }
}

impl CredentialsProvider for HardcodedCredentialsProvider {
    fn get_credentials(
        &self,
    ) -> Result<Option<BasicCredentials>, Box<dyn CredentialsProviderError + 'static>> {
        Ok(self.creds.clone())
    }
}

/// A credentials provider that uses an underlying TokenBasicCredentialsGenerator for generating
/// credentials.
pub struct TokenBasicCredentialsProvider<TP: TimeProvider> {
    username: String,
    generator: TokenBasicCredentialsGenerator<TP>,
}

impl<TP: TimeProvider> TokenBasicCredentialsProvider<TP> {
    pub fn new(username: impl AsRef<str>, generator: TokenBasicCredentialsGenerator<TP>) -> Self {
        Self {
            username: username.as_ref().to_owned(),
            generator,
        }
    }
}

impl<TP: TimeProvider> CredentialsProvider for TokenBasicCredentialsProvider<TP> {
    fn get_credentials(
        &self,
    ) -> Result<Option<BasicCredentials>, Box<dyn CredentialsProviderError + 'static>> {
        Ok(Some(self.generator.generate_for(&self.username).map_err(
            |err| {
                let boxed_err: Box<dyn CredentialsProviderError + 'static> = Box::new(err);
                boxed_err
            },
        )?))
    }
}

/// All possible types of built-in credential providers.
pub enum AnyCredentialsProvider<TP: TimeProvider = SystemTimeProvider> {
    Hardcoded(HardcodedCredentialsProvider),
    Token(TokenBasicCredentialsProvider<TP>),
}

impl<TP: TimeProvider> CredentialsProvider for AnyCredentialsProvider<TP> {
    fn get_credentials(
        &self,
    ) -> Result<Option<BasicCredentials>, Box<dyn CredentialsProviderError + 'static>> {
        match self {
            Self::Hardcoded(inner) => inner.get_credentials(),
            Self::Token(inner) => inner.get_credentials(),
        }
    }
}
