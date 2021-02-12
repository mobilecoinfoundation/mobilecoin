// Copyright (c) 2018-2021 The MobileCoin Foundation

//! GRPC credentials support

use grpcio::{Error as GrpcError, RpcStatusCode};
use mc_util_grpc::BasicCredentials;
use mc_util_uri::ConnectionUri;
use std::{
    fmt::{Debug, Display},
    marker::PhantomData,
};

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
    type Uri: ConnectionUri;

    fn get_credentials(
        &self,
        uri: &Self::Uri,
    ) -> Result<Option<BasicCredentials>, Box<dyn CredentialsProviderError + 'static>>;
}

/// A credentials provider that gets the credentials from the URI's user/password fields.
pub struct UriUserPassCredentialsProvider<URI> {
    _uri: PhantomData<URI>,
}

impl<URI: ConnectionUri> Default for UriUserPassCredentialsProvider<URI> {
    fn default() -> Self {
        Self {
            _uri: Default::default(),
        }
    }
}

impl<URI: ConnectionUri> CredentialsProvider for UriUserPassCredentialsProvider<URI> {
    type Uri = URI;

    fn get_credentials(
        &self,
        uri: &Self::Uri,
    ) -> Result<Option<BasicCredentials>, Box<dyn CredentialsProviderError + 'static>> {
        Ok(Some(BasicCredentials::new(
            &uri.username(),
            &uri.password(),
        )))
    }
}

use mc_common::time::TimeProvider;
use mc_util_grpc::TokenBasicCredentialsGenerator;

/// A credentials provider that uses an underlying TokenBasicCredentialsGenerator for generating
/// credentials.
pub struct TokenBasicCredentialsProvider<TP: TimeProvider, URI> {
    generator: TokenBasicCredentialsGenerator<TP>,
    _uri: PhantomData<URI>,
}

impl<TP: TimeProvider, URI: ConnectionUri> From<TokenBasicCredentialsGenerator<TP>>
    for TokenBasicCredentialsProvider<TP, URI>
{
    fn from(generator: TokenBasicCredentialsGenerator<TP>) -> Self {
        Self {
            generator,
            _uri: Default::default(),
        }
    }
}

impl<TP: TimeProvider, URI: ConnectionUri> CredentialsProvider
    for TokenBasicCredentialsProvider<TP, URI>
{
    type Uri = URI;

    fn get_credentials(
        &self,
        uri: &Self::Uri,
    ) -> Result<Option<BasicCredentials>, Box<dyn CredentialsProviderError + 'static>> {
        let username = uri.username();
        if username.is_empty() {
            return Err(Box::new(format!(
                "TokenBasicCredentialsProvider requires a username in the url ({})",
                uri
            )));
        }

        Ok(Some(self.generator.generate_for(&username).map_err(
            |err| {
                let boxed_err: Box<dyn CredentialsProviderError + 'static> = Box::new(err);
                boxed_err
            },
        )?))
    }
}
