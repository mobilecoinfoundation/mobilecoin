// Copyright (c) 2018-2020 MobileCoin Inc.

//! GRPC authentication utilities.

pub mod token_authenticator;

use displaydoc::Display;
use std::{fmt, str};

pub trait Authenticator {
    type User: Send + 'static;
    type Error: fmt::Display;
    fn authenticate(
        &self,
        maybe_credentials: Option<BasicCredentials>,
    ) -> Result<Self::User, Self::Error>;
}

pub struct BasicCredentials {
    username: String,
    password: String,
}

#[derive(Display)]
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
}
