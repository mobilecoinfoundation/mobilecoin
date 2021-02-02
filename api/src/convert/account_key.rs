//! Convert to/from external::AccountKey

use crate::{convert::ConversionError, external};
use mc_account_keys::AccountKey;
use std::convert::TryFrom;

impl From<&AccountKey> for external::AccountKey {
    fn from(src: &AccountKey) -> Self {
        let mut dst = external::AccountKey::new();

        dst.set_view_private_key(external::RistrettoPrivate::from(src.view_private_key()));
        dst.set_spend_private_key(external::RistrettoPrivate::from(src.spend_private_key()));

        if let Some(url) = src.fog_report_url() {
            dst.set_fog_report_url(url.to_string());
        }

        if let Some(spki) = src.fog_authority_spki() {
            dst.set_fog_authority_spki(spki.to_vec());
        }

        if let Some(key) = src.fog_report_id() {
            dst.set_fog_report_id(key.to_string());
        }

        dst
    }
}

impl TryFrom<&external::AccountKey> for AccountKey {
    type Error = ConversionError;

    fn try_from(src: &external::AccountKey) -> Result<Self, Self::Error> {
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

        if src.fog_report_url.is_empty() {
            Ok(AccountKey::new(&spend_private_key, &view_private_key))
        } else {
            Ok(AccountKey::new_with_fog(
                &spend_private_key,
                &view_private_key,
                &src.fog_report_url,
                src.fog_report_id.clone(),
                &src.fog_authority_spki[..],
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    // Test converting between external::AccountKey and account_keys::AccountKey
    #[test]
    fn test_account_key_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        // without fog_report_url
        {
            // account_keys -> external
            let account_key = AccountKey::random(&mut rng);
            let proto_credentials = external::AccountKey::from(&account_key);
            assert_eq!(
                *proto_credentials.get_view_private_key(),
                external::RistrettoPrivate::from(account_key.view_private_key())
            );
            assert_eq!(
                *proto_credentials.get_spend_private_key(),
                external::RistrettoPrivate::from(account_key.spend_private_key())
            );
            assert_eq!(proto_credentials.fog_report_url, String::from(""));

            assert_eq!(proto_credentials.fog_authority_spki.len(), 0);

            assert_eq!(proto_credentials.fog_report_id, String::from(""));

            // external -> account_keys
            let account_key2 = AccountKey::try_from(&proto_credentials).unwrap();
            assert_eq!(account_key, account_key2);
        }

        // with valid fog_report_url
        {
            // account_keys -> external
            let tmp_account_key = AccountKey::random(&mut rng);
            let account_key = AccountKey::new_with_fog(
                tmp_account_key.spend_private_key(),
                tmp_account_key.view_private_key(),
                "fog://test.mobilecoin.com".to_string(),
                "99".to_string(),
                vec![9, 9, 9, 9],
            );

            let proto_credentials = external::AccountKey::from(&account_key);
            assert_eq!(
                *proto_credentials.get_view_private_key(),
                external::RistrettoPrivate::from(account_key.view_private_key())
            );
            assert_eq!(
                *proto_credentials.get_spend_private_key(),
                external::RistrettoPrivate::from(account_key.spend_private_key())
            );
            assert_eq!(
                proto_credentials.fog_report_url,
                String::from("fog://test.mobilecoin.com")
            );

            assert_eq!(proto_credentials.fog_authority_spki, vec![9, 9, 9, 9],);

            assert_eq!(proto_credentials.fog_report_id, String::from("99"));

            // external -> account_keys
            let account_key2 = AccountKey::try_from(&proto_credentials).unwrap();
            assert_eq!(account_key, account_key2);
        }
    }
}
