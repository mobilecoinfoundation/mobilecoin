// Copyright (c) 2018-2021 The MobileCoin Foundation

//! GRPC authenticator that relies on a shared secret for generating and
//! verifying tokens.

use super::*;

use displaydoc::Display;
use hmac::{Hmac, Mac, NewMac};
use mc_common::time::TimeProvider;
use std::{str, time::Duration};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Token-based authentication: An object that implements `Authenticator`,
/// allowing to authenticate users using HMAC-generated tokens.
pub struct TokenAuthenticator<TP: TimeProvider> {
    /// Secret shared between the authenticator and then token generator,
    /// allowing for generated tokens to be cryptographically-verified by
    /// the authenticator.
    shared_secret: [u8; 32],

    /// The maximum duration a token is valid for.
    max_token_lifetime: Duration,

    /// Time provider.
    time_provider: TP,
}

impl<TP: TimeProvider> Drop for TokenAuthenticator<TP> {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

impl<TP: TimeProvider> Authenticator for TokenAuthenticator<TP> {
    fn authenticate(
        &self,
        maybe_credentials: Option<BasicCredentials>,
    ) -> Result<String, AuthenticatorError> {
        let credentials = maybe_credentials.ok_or(AuthenticatorError::Unauthenticated)?;
        let mut parts = credentials.password.split(':');
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
        if !self.is_valid_time(timestamp)? {
            return Err(AuthenticatorError::ExpiredAuthorizationToken);
        }
        if !self.is_valid_signature(&format!("{}:{}", username, timestamp), signature)? {
            return Err(AuthenticatorError::InvalidAuthorizationToken);
        }
        Ok(credentials.username)
    }
}

impl<TP: TimeProvider> TokenAuthenticator<TP> {
    pub fn new(shared_secret: [u8; 32], max_token_lifetime: Duration, time_provider: TP) -> Self {
        Self {
            shared_secret,
            max_token_lifetime,
            time_provider,
        }
    }

    fn is_valid_time(&self, timestamp: &str) -> Result<bool, AuthenticatorError> {
        let token_time: Duration = Duration::from_secs(
            timestamp
                .parse()
                .map_err(|_| AuthenticatorError::InvalidAuthorizationToken)?,
        );
        let our_time = self
            .time_provider
            .from_epoch()
            .map_err(|_| AuthenticatorError::ExpiredAuthorizationToken)?;
        let distance: Duration = our_time
            .checked_sub(token_time)
            .unwrap_or_else(|| token_time - our_time);
        Ok(distance < self.max_token_lifetime)
    }

    fn is_valid_signature(&self, data: &str, signature: &str) -> Result<bool, AuthenticatorError> {
        let their_suffix: Vec<u8> =
            hex::decode(signature).map_err(|_| AuthenticatorError::InvalidAuthorizationToken)?;

        let mut mac = Hmac::<sha2::Sha256>::new_varkey(&self.shared_secret)
            .map_err(|_| AuthenticatorError::Other("Invalid HMAC key".to_owned()))?;
        mac.update(data.as_bytes());
        let our_signature = mac.finalize().into_bytes();

        let our_suffix: &[u8] = &our_signature[..10];
        Ok(bool::from(our_suffix.ct_eq(&their_suffix)))
    }
}

/// Error values for token generator.
#[derive(Display, Debug)]
pub enum TokenBasicCredentialsGeneratorError {
    /// TimeProvider error
    TimeProvider,

    /// Invalid HMAC key
    InvalidHmacKey,
}

/// Token generator - an object that can generate HMAC authentication tokens.
pub struct TokenBasicCredentialsGenerator<TP: TimeProvider> {
    shared_secret: [u8; 32],
    time_provider: TP,
}

impl<TP: TimeProvider> TokenBasicCredentialsGenerator<TP> {
    pub fn new(shared_secret: [u8; 32], time_provider: TP) -> Self {
        Self {
            shared_secret,
            time_provider,
        }
    }

    pub fn generate_for(
        &self,
        user_id: &str,
    ) -> Result<BasicCredentials, TokenBasicCredentialsGeneratorError> {
        let current_time_seconds = self
            .time_provider
            .from_epoch()
            .map_err(|_| TokenBasicCredentialsGeneratorError::TimeProvider)?
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

impl<TP: TimeProvider> Drop for TokenBasicCredentialsGenerator<TP> {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const TOKEN_MAX_LIFETIME: Duration = Duration::from_secs(60);
    use mc_common::time::{MockTimeProvider, SystemTimeProvider};

    #[test]
    fn valid_token_authenticates_successfully() {
        let shared_secret = [3; 32];
        const TEST_USERNAME: &str = "test user";

        let generator =
            TokenBasicCredentialsGenerator::new(shared_secret, SystemTimeProvider::default());
        let authenticator = TokenAuthenticator::new(
            shared_secret,
            TOKEN_MAX_LIFETIME,
            SystemTimeProvider::default(),
        );

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
        let authenticator = TokenAuthenticator::new(
            shared_secret,
            TOKEN_MAX_LIFETIME,
            SystemTimeProvider::default(),
        );

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

        let generator =
            TokenBasicCredentialsGenerator::new(shared_secret, SystemTimeProvider::default());

        // Signature will fail if authenticator uses a different shared secret.
        let authenticator =
            TokenAuthenticator::new([4; 32], TOKEN_MAX_LIFETIME, SystemTimeProvider::default());

        let creds = generator.generate_for(TEST_USERNAME).unwrap();

        // We expect this to panic.
        let _ = authenticator.authenticate(Some(creds)).unwrap();
    }

    #[test]
    fn is_valid_time_rejects_expired() {
        let time_provider = MockTimeProvider::default();

        let authenticator =
            TokenAuthenticator::new([4; 32], TOKEN_MAX_LIFETIME, time_provider.clone());

        // Initially, we should be valid.
        let now_in_seconds = time_provider.from_epoch().unwrap().as_secs();
        assert!(authenticator
            .is_valid_time(&now_in_seconds.to_string())
            .unwrap());

        // Set the time such that we are no longer considered vald.
        let expired = time_provider.from_epoch().unwrap() + TOKEN_MAX_LIFETIME;
        time_provider.set_cur_from_epoch(expired);

        assert!(!authenticator
            .is_valid_time(&now_in_seconds.to_string())
            .unwrap());
    }
}
