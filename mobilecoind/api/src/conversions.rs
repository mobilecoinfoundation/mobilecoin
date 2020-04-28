// Copyright (c) 2018-2020 MobileCoin Inc.

//! provides conversions between types used in libmobilecoin and types from mobilecoind_api

use crate::mobilecoind_api;
use mc_api::external;
use mc_transaction_core::account_keys;
use std::convert::{From, TryFrom};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ConversionError {
    Key(mc_crypto_keys::KeyError),
    MobilecoinApiConversion(mc_api::ConversionError),
    FeeMismatch,
    IndexOutOfBounds,
}

impl From<mc_crypto_keys::KeyError> for ConversionError {
    fn from(src: mc_crypto_keys::KeyError) -> Self {
        Self::Key(src)
    }
}

impl From<mc_api::ConversionError> for ConversionError {
    fn from(src: mc_api::ConversionError) -> Self {
        Self::MobilecoinApiConversion(src)
    }
}

impl From<&account_keys::AccountKey> for mobilecoind_api::AccountKey {
    fn from(src: &account_keys::AccountKey) -> Self {
        let mut dst = mobilecoind_api::AccountKey::new();

        dst.set_view_private_key(external::RistrettoPrivate::from(src.view_private_key()));
        dst.set_spend_private_key(external::RistrettoPrivate::from(src.spend_private_key()));

        if let Some(fqdn) = src.fog_url() {
            dst.set_fog_fqdn(fqdn.to_string());
        }

        dst
    }
}

impl TryFrom<&mobilecoind_api::AccountKey> for account_keys::AccountKey {
    type Error = ConversionError;

    fn try_from(src: &mobilecoind_api::AccountKey) -> Result<Self, Self::Error> {
        let spend_private_key = src
            .spend_private_key
            .as_ref()
            .ok_or(mc_crypto_keys::KeyError::LengthMismatch(0, 32))
            .and_then(|key| mc_crypto_keys::RistrettoPrivate::try_from(&key.data[..]))?;

        let view_private_key = src
            .view_private_key
            .as_ref()
            .ok_or(mc_crypto_keys::KeyError::LengthMismatch(0, 32))
            .and_then(|key| mc_crypto_keys::RistrettoPrivate::try_from(&key.data[..]))?;

        if src.fog_fqdn.is_empty() {
            Ok(account_keys::AccountKey::new(
                &spend_private_key,
                &view_private_key,
            ))
        } else {
            Ok(account_keys::AccountKey::new_with_fog(
                &spend_private_key,
                &view_private_key,
                &src.fog_fqdn,
            ))
        }
    }
}

impl From<&account_keys::PublicAddress> for mobilecoind_api::PublicAddress {
    fn from(src: &account_keys::PublicAddress) -> Self {
        let mut dst = mobilecoind_api::PublicAddress::new();

        dst.set_view_public_key(external::RistrettoPublic::from(src.view_public_key()));
        dst.set_spend_public_key(external::RistrettoPublic::from(src.spend_public_key()));

        if let Some(fqdn) = src.fog_url() {
            dst.set_fog_fqdn(fqdn.to_string());
        }

        dst
    }
}

impl TryFrom<&mobilecoind_api::PublicAddress> for account_keys::PublicAddress {
    type Error = ConversionError;

    fn try_from(src: &mobilecoind_api::PublicAddress) -> Result<Self, Self::Error> {
        let spend_public_key = src
            .spend_public_key
            .as_ref()
            .ok_or(mc_crypto_keys::KeyError::LengthMismatch(0, 32))
            .and_then(|key| mc_crypto_keys::RistrettoPublic::try_from(&key.data[..]))?;

        let view_public_key = src
            .view_public_key
            .as_ref()
            .ok_or(mc_crypto_keys::KeyError::LengthMismatch(0, 32))
            .and_then(|key| mc_crypto_keys::RistrettoPublic::try_from(&key.data[..]))?;

        if src.fog_fqdn.is_empty() {
            Ok(account_keys::PublicAddress::new(
                &spend_public_key,
                &view_public_key,
            ))
        } else {
            Ok(account_keys::PublicAddress::new_with_fog(
                &spend_public_key,
                &view_public_key,
                &src.fog_fqdn,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::mobilecoind_api;
    use mc_api::external;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_transaction_core::account_keys;
    use rand::{rngs::StdRng, SeedableRng};
    use std::convert::{From, TryFrom};

    // Test converting between mobilecoind_api::AccountKey and account_keys::AccountKey
    #[test_with_logger]
    fn test_account_key_conversion(_logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        // without fog_fqdn
        {
            // account_keys -> mobilecoind_api
            let account_key = account_keys::AccountKey::random(&mut rng);
            let proto_credentials = mobilecoind_api::AccountKey::from(&account_key);
            assert_eq!(
                *proto_credentials.get_view_private_key(),
                external::RistrettoPrivate::from(account_key.view_private_key())
            );
            assert_eq!(
                *proto_credentials.get_spend_private_key(),
                external::RistrettoPrivate::from(account_key.spend_private_key())
            );
            assert_eq!(proto_credentials.fog_fqdn, String::from(""));

            // mobilecoind_api -> account_keys
            let account_key2 = account_keys::AccountKey::try_from(&proto_credentials).unwrap();
            assert_eq!(account_key, account_key2);
        }

        // with valid fog_fqdn
        {
            // account_keys -> mobilecoind_api
            let tmp_account_key = account_keys::AccountKey::random(&mut rng);
            let account_key = account_keys::AccountKey::new_with_fog(
                tmp_account_key.spend_private_key(),
                tmp_account_key.view_private_key(),
                "test.mobilecoin.com".to_string(),
            );

            let proto_credentials = mobilecoind_api::AccountKey::from(&account_key);
            assert_eq!(
                *proto_credentials.get_view_private_key(),
                external::RistrettoPrivate::from(account_key.view_private_key())
            );
            assert_eq!(
                *proto_credentials.get_spend_private_key(),
                external::RistrettoPrivate::from(account_key.spend_private_key())
            );
            assert_eq!(
                proto_credentials.fog_fqdn,
                String::from("test.mobilecoin.com")
            );

            // mobilecoind_api -> account_keys
            let account_key2 = account_keys::AccountKey::try_from(&proto_credentials).unwrap();
            assert_eq!(account_key, account_key2);
        }
    }

    // Test converting between mobilecoind_api::PublicAddress and account_keys::PublicAddress
    #[test_with_logger]
    fn test_public_address_conversion(_logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        // without fog_fqdn
        {
            // public_addresss -> mobilecoind_api
            let public_address = account_keys::AccountKey::random(&mut rng).default_subaddress();
            let proto_credentials = mobilecoind_api::PublicAddress::from(&public_address);
            assert_eq!(
                *proto_credentials.get_view_public_key(),
                external::RistrettoPublic::from(public_address.view_public_key())
            );
            assert_eq!(
                *proto_credentials.get_spend_public_key(),
                external::RistrettoPublic::from(public_address.spend_public_key())
            );
            assert_eq!(proto_credentials.fog_fqdn, String::from(""));

            // mobilecoind_api -> public_addresss
            let public_address2 =
                account_keys::PublicAddress::try_from(&proto_credentials).unwrap();
            assert_eq!(public_address, public_address2);
        }

        // with valid fog_fqdn
        {
            // public_addresss -> mobilecoind_api
            let tmp_public_address =
                account_keys::AccountKey::random(&mut rng).default_subaddress();
            let public_address = account_keys::PublicAddress::new_with_fog(
                tmp_public_address.spend_public_key(),
                tmp_public_address.view_public_key(),
                "test.mobilecoin.com".to_string(),
            );

            let proto_credentials = mobilecoind_api::PublicAddress::from(&public_address);
            assert_eq!(
                *proto_credentials.get_view_public_key(),
                external::RistrettoPublic::from(public_address.view_public_key())
            );
            assert_eq!(
                *proto_credentials.get_spend_public_key(),
                external::RistrettoPublic::from(public_address.spend_public_key())
            );
            assert_eq!(
                proto_credentials.fog_fqdn,
                String::from("test.mobilecoin.com")
            );

            // mobilecoind_api -> public_addresss
            let public_address2 =
                account_keys::PublicAddress::try_from(&proto_credentials).unwrap();
            assert_eq!(public_address, public_address2);
        }
    }
}
