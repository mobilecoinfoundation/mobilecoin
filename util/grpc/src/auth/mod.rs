// Copyright (c) 2018-2020 MobileCoin Inc.

//! GRPC authentication utilities.

pub mod anonymous_authenticator;
pub mod token_authenticator;

use displaydoc::Display;
use grpcio::Metadata;
use std::{ops::Deref, str};

/// Error values for authentication.
#[derive(Display, Debug)]
pub enum AuthenticatorError {
    /// Unauthenticated
    Unauthenticated,

    /// Invalid user authorization token
    InvalidAuthorizationToken,

    /// Expired user authorization token
    ExpiredAuthorizationToken,

    /// Other: {0}
    Other(String),
}

/// Interface for performing an authentication using `BasicCredentials`, resulting in a String
/// username or an error.
pub trait Authenticator {
    fn authenticate(
        &self,
        maybe_credentials: Option<BasicCredentials>,
    ) -> Result<String, AuthenticatorError>;
}

/// Standard username/password credentials.
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
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_owned(),
            password: password.to_owned(),
        }
    }

    /// Try and construct `BasicCredentials` from an HTTP Basic Authorization header.
    pub fn try_from(header_value: &[u8]) -> Result<Self, AuthorizationHeaderError> {
        let header = str::from_utf8(header_value)
            .map_err(|_| AuthorizationHeaderError::InvalidAuthorizationHeader)?;
        let mut header_parts = header.split(" ");

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
        let mut credential_parts = concatenated_values.splitn(2, ":");

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

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn authorization_header(&self) -> String {
        format!(
            "Basic {}",
            base64::encode(format!("{}:{}", self.username, self.password))
        )
    }
}

/// Error values for the `authorize` helper method.
#[derive(Display, Debug)]
pub enum AuthorizeError {
    /// Authentication error: {0}
    Authentication(AuthenticatorError),

    /// Authorization header error: {0},
    AuthorizationHeader(AuthorizationHeaderError),
}

impl From<AuthenticatorError> for AuthorizeError {
    fn from(src: AuthenticatorError) -> Self {
        Self::Authentication(src)
    }
}

impl From<AuthorizationHeaderError> for AuthorizeError {
    fn from(src: AuthorizationHeaderError) -> Self {
        Self::AuthorizationHeader(src)
    }
}

/// A utility method for performing authorization using the HTTP Authorization header in an
/// `Metadata` object.
pub fn authorize<Auth: Authenticator>(
    authenticator: impl Deref<Target = Auth>,
    metadata: &Metadata,
) -> Result<String, AuthorizeError> {
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

    Ok(authenticator.authenticate(creds)?)
}

#[cfg(test)]
mod test {
    use super::*;
    use anonymous_authenticator::{AnonymousAuthenticator, ANONYMOUS_USER};
    use grpcio::MetadataBuilder;
    use token_authenticator::{TokenAuthenticator, TokenBasicCredentialsGenerator};

    #[test]
    fn authorize_anonymous() {
        let authenticator = AnonymousAuthenticator::default();

        // Authorizing without any headers should work.
        let metadata = MetadataBuilder::new().build();
        let user = authorize(&authenticator, &metadata).expect("authorize failed");
        assert_eq!(user, ANONYMOUS_USER);

        // Authorizing with an unrelated header should work.
        let mut metadata_builder = MetadataBuilder::new();
        metadata_builder.add_str("test", "header").unwrap();
        let user = authorize(&authenticator, &metadata_builder.build()).expect("authorize failed");
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
            if authorize(&authenticator, &metadata_builder.build()).is_ok() {
                panic!("Unexpected success with header {:?}", test_header_value);
            }
        }

        // Authorizing with a valid Authorization error should succeed.
        let mut metadata_builder = MetadataBuilder::new();
        metadata_builder
            .add_str("Authorization", "Basic YTpi")
            .unwrap();
        let user = authorize(&authenticator, &metadata_builder.build()).expect("authorize failed");
        assert_eq!(user, ANONYMOUS_USER);
    }

    #[test]
    fn authorize_token() {
        let shared_secret = [66; 32];
        let authenticator = TokenAuthenticator::new(shared_secret.clone());
        const TEST_USERNAME: &str = "user123";

        // Authorizing without any headers should fail.
        let metadata = MetadataBuilder::new().build();
        assert!(authorize(&authenticator, &metadata).is_err());

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
            if authorize(&authenticator, &metadata_builder.build()).is_ok() {
                panic!("Unexpected success with header {:?}", test_header_value);
            }
        }

        // Authorizing with a valid Authorization header should succeed.
        let generator = TokenBasicCredentialsGenerator::new(shared_secret.clone());
        let creds = generator
            .generate_for(TEST_USERNAME)
            .expect("failed generating token");

        let mut metadata_builder = MetadataBuilder::new();
        metadata_builder
            .add_str("Authorization", &creds.authorization_header())
            .unwrap();
        let username =
            authorize(&authenticator, &metadata_builder.build()).expect("authorize failed");
        assert_eq!(username, TEST_USERNAME);
    }
}
