// Copyright (c) 2018-2021 The MobileCoin Foundation

//! GRPC authentication utilities.

mod anonymous_authenticator;
mod token_authenticator;

pub use anonymous_authenticator::{AnonymousAuthenticator, ANONYMOUS_USER};
pub use token_authenticator::{
    TokenAuthenticator, TokenBasicCredentialsGenerator, TokenBasicCredentialsGeneratorError,
};

use displaydoc::Display;
use grpcio::{
    CallOption, Error as GrpcError, Metadata, MetadataBuilder, RpcContext, RpcStatus, RpcStatusCode,
};
use std::str;

/// Error values for authentication.
#[derive(Display, Debug)]
pub enum AuthenticatorError {
    /// Unauthenticated
    Unauthenticated,

    /// Invalid user authorization token
    InvalidAuthorizationToken,

    /// Expired user authorization token
    ExpiredAuthorizationToken,

    /// Authorization header error: {0}
    AuthorizationHeader(AuthorizationHeaderError),

    /// Other: {0}
    Other(String),
}

impl From<AuthorizationHeaderError> for AuthenticatorError {
    fn from(src: AuthorizationHeaderError) -> Self {
        Self::AuthorizationHeader(src)
    }
}

impl<T> From<AuthenticatorError> for Result<T, RpcStatus> {
    fn from(src: AuthenticatorError) -> Result<T, RpcStatus> {
        Err(RpcStatus::with_message(
            RpcStatusCode::UNAUTHENTICATED,
            src.to_string(),
        ))
    }
}

/// Interface for performing an authentication using `BasicCredentials`,
/// resulting in a String username or an error.
pub trait Authenticator {
    fn authenticate(
        &self,
        maybe_credentials: Option<BasicCredentials>,
    ) -> Result<String, AuthenticatorError>;

    fn authenticate_metadata(&self, metadata: &Metadata) -> Result<String, AuthenticatorError> {
        let creds = metadata
            .iter()
            .find_map(|(key, value)| {
                if key.to_lowercase() == "authorization" {
                    Some(value)
                } else {
                    None
                }
            })
            .map(BasicCredentials::try_from)
            .transpose()?;

        self.authenticate(creds)
    }

    fn authenticate_rpc(&self, context: &RpcContext) -> Result<String, AuthenticatorError> {
        self.authenticate_metadata(context.request_headers())
    }
}

/// Standard username/password credentials.
#[derive(Clone, Default)]
pub struct BasicCredentials {
    username: String,
    password: String,
}

#[derive(Display, Debug)]
pub enum AuthorizationHeaderError {
    /// Unsupported authorization method
    UnsupportedAuthorizationMethod,

    /// Invalid authorization header
    InvalidAuthorizationHeader,

    /// Invalid credentials
    InvalidCredentials,
}

impl BasicCredentials {
    /// Construct a new `BasicCredentials` using provided username and password.
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_owned(),
            password: password.to_owned(),
        }
    }

    /// Try and construct `BasicCredentials` from an HTTP Basic Authorization
    /// header.
    pub fn try_from(header_value: &[u8]) -> Result<Self, AuthorizationHeaderError> {
        let header = str::from_utf8(header_value)
            .map_err(|_| AuthorizationHeaderError::InvalidAuthorizationHeader)?;
        let mut header_parts = header.split(' ');

        if "Basic"
            != header_parts
                .next()
                .ok_or(AuthorizationHeaderError::InvalidAuthorizationHeader)?
        {
            return Err(AuthorizationHeaderError::UnsupportedAuthorizationMethod);
        }

        let base64_value = header_parts
            .next()
            .ok_or(AuthorizationHeaderError::InvalidAuthorizationHeader)?;
        let concatenated_values_bytes = base64::decode(base64_value)
            .map_err(|_| AuthorizationHeaderError::InvalidAuthorizationHeader)?;
        let concatenated_values = str::from_utf8(&concatenated_values_bytes)
            .map_err(|_| AuthorizationHeaderError::InvalidCredentials)?;
        let mut credential_parts = concatenated_values.splitn(2, ':');

        Ok(Self {
            username: credential_parts
                .next()
                .ok_or(AuthorizationHeaderError::InvalidCredentials)?
                .to_string(),
            password: credential_parts
                .next()
                .ok_or(AuthorizationHeaderError::InvalidCredentials)?
                .to_string(),
        })
    }

    /// Get username.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get password.
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Convenience method for constructing an HTTP Authorization header based
    /// on the username and password stored in this object.
    pub fn authorization_header(&self) -> String {
        format!(
            "Basic {}",
            base64::encode(format!("{}:{}", self.username, self.password))
        )
    }

    /// Convenience method for constructing a `grpcio::CallOption` object that
    /// passes an Authorization header if this object contains non-empty
    /// username or password.
    pub fn call_option(&self) -> Result<CallOption, GrpcError> {
        let mut call_option = CallOption::default();
        if !self.username.is_empty() || !self.password.is_empty() {
            let mut metadata_builder = MetadataBuilder::new();
            metadata_builder.add_str("Authorization", &self.authorization_header())?;
            call_option = call_option.headers(metadata_builder.build());
        }
        Ok(call_option)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anonymous_authenticator::{AnonymousAuthenticator, ANONYMOUS_USER};
    use grpcio::MetadataBuilder;
    use mc_common::time::SystemTimeProvider;
    use std::time::Duration;
    use token_authenticator::{TokenAuthenticator, TokenBasicCredentialsGenerator};

    const TOKEN_MAX_LIFETIME: Duration = Duration::from_secs(60);

    #[test]
    fn authenticate_anonymous() {
        let authenticator = AnonymousAuthenticator::default();

        // Authorizing without any headers should work.
        let metadata = MetadataBuilder::new().build();
        let user = authenticator
            .authenticate_metadata(&metadata)
            .expect("authenticate failed");
        assert_eq!(user, ANONYMOUS_USER);

        // Authorizing with an unrelated header should work.
        let mut metadata_builder = MetadataBuilder::new();
        metadata_builder.add_str("test", "header").unwrap();
        let user = authenticator
            .authenticate_metadata(&metadata_builder.build())
            .expect("authenticate failed");
        assert_eq!(user, ANONYMOUS_USER);

        // Authorizing with an invalid Authorization header should fail.
        for test_header_value in &[
            "NotBasic",
            "NotBasic XXX",
            "Basic",
            "Basic XXX",
            "Basic YWI=",
        ] {
            let mut metadata_builder = MetadataBuilder::new();
            metadata_builder
                .add_str("Authorization", test_header_value)
                .unwrap();
            if authenticator
                .authenticate_metadata(&metadata_builder.build())
                .is_ok()
            {
                panic!("Unexpected success with header {:?}", test_header_value);
            }
        }

        // Authorizing with a valid Authorization error should succeed.
        let mut metadata_builder = MetadataBuilder::new();
        metadata_builder
            .add_str("Authorization", "Basic YTpi")
            .unwrap();
        let user = authenticator
            .authenticate_metadata(&metadata_builder.build())
            .expect("authenticate failed");
        assert_eq!(user, ANONYMOUS_USER);
    }

    #[test]
    fn authenticate_token() {
        let shared_secret = [66; 32];
        let authenticator = TokenAuthenticator::new(
            shared_secret,
            TOKEN_MAX_LIFETIME,
            SystemTimeProvider::default(),
        );
        const TEST_USERNAME: &str = "user123";

        // Authorizing without any headers should fail.
        let metadata = MetadataBuilder::new().build();
        assert!(authenticator.authenticate_metadata(&metadata).is_err());

        // Authorizing with an invalid Authorization header should fail.
        for test_header_value in &[
            "NotBasic",
            "NotBasic XXX",
            "Basic",
            "Basic XXX",
            "Basic YWI=",
        ] {
            let mut metadata_builder = MetadataBuilder::new();
            metadata_builder
                .add_str("Authorization", test_header_value)
                .unwrap();
            if authenticator
                .authenticate_metadata(&metadata_builder.build())
                .is_ok()
            {
                panic!("Unexpected success with header {:?}", test_header_value);
            }
        }

        // Authorizing with a valid Authorization header should succeed.
        let generator =
            TokenBasicCredentialsGenerator::new(shared_secret, SystemTimeProvider::default());
        let creds = generator
            .generate_for(TEST_USERNAME)
            .expect("failed generating token");

        let mut metadata_builder = MetadataBuilder::new();
        metadata_builder
            .add_str("Authorization", &creds.authorization_header())
            .unwrap();
        let username = authenticator
            .authenticate_metadata(&metadata_builder.build())
            .expect("authenticate failed");
        assert_eq!(username, TEST_USERNAME);
    }
}
