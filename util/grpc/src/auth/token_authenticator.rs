// Copyright (c) 2018-2020 MobileCoin Inc.

//! GRPC authenticator that relies on a shared secret for generating and verifying tokens.

use super::*;

use displaydoc::Display;
use hmac::{Hmac, Mac, NewMac};
use std::{
    str,
    time::{Duration, SystemTime},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// The maximum duration a token is valid for.
pub const TOKEN_MAX_LIFETIME: Duration = Duration::from_secs(86400);

/// Token-based authentication: An object that implements `Authenticator`, allowing to authenticate
/// users using HMAC-generated tokens.
#[derive(Zeroize)]
pub struct TokenAuthenticator {
    shared_secret: [u8; 32],
}

impl Authenticator for TokenAuthenticator {
    fn authenticate(
        &self,
        maybe_credentials: Option<BasicCredentials>,
    ) -> Result<String, AuthenticatorError> {
        let credentials = maybe_credentials.ok_or(AuthenticatorError::Unauthenticated)?;
        let mut parts = credentials.password.split(":");
        let username = parts
            .next()
            .ok_or(AuthenticatorError::InvalidAuthorizationToken)?;
        let timestamp = parts
            .next()
            .ok_or(AuthenticatorError::InvalidAuthorizationToken)?;
        let signature = parts
            .next()
            .ok_or(AuthenticatorError::InvalidAuthorizationToken)?;
        if parts.next().is_some() {
            return Err(AuthenticatorError::InvalidAuthorizationToken);
        }
        if username != credentials.username {
            return Err(AuthenticatorError::InvalidAuthorizationToken);
        }
        if !self.is_valid_time(timestamp, SystemTime::now())? {
            return Err(AuthenticatorError::ExpiredAuthorizationToken);
        }
        if !self.is_valid_signature(&format!("{}:{}", username, timestamp), signature)? {
            return Err(AuthenticatorError::InvalidAuthorizationToken);
        }
        Ok(credentials.username)
    }
}

impl TokenAuthenticator {
    pub fn new(shared_secret: [u8; 32]) -> Self {
        Self { shared_secret }
    }

    fn is_valid_time(&self, timestamp: &str, now: SystemTime) -> Result<bool, AuthenticatorError> {
        let token_time: Duration = Duration::from_secs(
            timestamp
                .parse()
                .map_err(|_| AuthenticatorError::InvalidAuthorizationToken)?,
        );
        let our_time: Duration = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| AuthenticatorError::ExpiredAuthorizationToken)?;
        let distance: Duration = our_time
            .checked_sub(token_time)
            .unwrap_or_else(|| token_time - our_time);
        Ok(distance < TOKEN_MAX_LIFETIME)
    }

    fn is_valid_signature(&self, data: &str, signature: &str) -> Result<bool, AuthenticatorError> {
        let mut mac = Hmac::<sha2::Sha256>::new_varkey(&self.shared_secret)
            .map_err(|_| AuthenticatorError::Other("Invalid HMAC key".to_owned()))?;
        mac.update(data.as_bytes());
        let our_signature = mac.finalize().into_bytes();

        let their_suffix: Vec<u8> =
            hex::decode(signature).map_err(|_| AuthenticatorError::InvalidAuthorizationToken)?;
        let our_suffix: &[u8] = &our_signature[..10];
        Ok(bool::from(our_suffix.ct_eq(&their_suffix)))
    }
}

/// Error values for token generator.
#[derive(Display, Debug)]
pub enum TokenBasicCredentialsGeneratorError {
    /// SystemTime error
    SystemTime,

    /// Invalid HMAC key
    InvalidHmacKey,
}

/// Token generator - an object that can generate HMAC authentication tokens.
#[derive(Zeroize)]
pub struct TokenBasicCredentialsGenerator {
    shared_secret: [u8; 32],
}

impl TokenBasicCredentialsGenerator {
    pub fn new(shared_secret: [u8; 32]) -> Self {
        Self { shared_secret }
    }

    pub fn generate_for(
        &self,
        user_id: &str,
    ) -> Result<BasicCredentials, TokenBasicCredentialsGeneratorError> {
        let current_time_seconds = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| TokenBasicCredentialsGeneratorError::SystemTime)?
            .as_secs();
        let prefix = format!("{}:{}", user_id, current_time_seconds);

        let mut mac = Hmac::<sha2::Sha256>::new_varkey(&self.shared_secret)
            .map_err(|_| TokenBasicCredentialsGeneratorError::InvalidHmacKey)?;
        mac.update(prefix.as_bytes());
        let signature = mac.finalize().into_bytes();

        Ok(BasicCredentials::new(
            user_id,
            &format!(
                "{}:{}:{}",
                user_id,
                current_time_seconds,
                hex::encode(&signature[..10])
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_token_authenticates_successfully() {
        let shared_secret = [3; 32];
        const TEST_USERNAME: &str = "test user";

        let generator = TokenBasicCredentialsGenerator::new(shared_secret.clone());
        let authenticator = TokenAuthenticator::new(shared_secret);

        let creds = generator.generate_for(TEST_USERNAME).unwrap();
        let user = authenticator
            .authenticate(Some(creds))
            .expect("authenticate failed");
        assert_eq!(user, TEST_USERNAME);
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Unauthenticated")]
    fn missing_creds_fails_authentication() {
        let shared_secret = [3; 32];
        let authenticator = TokenAuthenticator::new(shared_secret);

        // We expect this to panic.
        let _ = authenticator.authenticate(None).unwrap();
    }

    #[test]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: InvalidAuthorizationToken"
    )]
    fn invalid_token_fails_authentication() {
        let shared_secret = [3; 32];
        const TEST_USERNAME: &str = "test user";

        let generator = TokenBasicCredentialsGenerator::new(shared_secret.clone());

        // Signature will fail if authenticator uses a different shared secret.
        let authenticator = TokenAuthenticator::new([4; 32]);

        let creds = generator.generate_for(TEST_USERNAME).unwrap();

        // We expect this to panic.
        let _ = authenticator.authenticate(Some(creds)).unwrap();
    }

    #[test]
    fn is_valid_time_rejects_expired() {
        let authenticator = TokenAuthenticator::new([4; 32]);

        let now = SystemTime::now();
        let now_in_seconds = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expired = now_in_seconds - TOKEN_MAX_LIFETIME.as_secs();

        assert!(authenticator
            .is_valid_time(&now_in_seconds.to_string(), now.clone())
            .unwrap());
        assert!(!authenticator
            .is_valid_time(&expired.to_string(), now)
            .unwrap());
    }
}
