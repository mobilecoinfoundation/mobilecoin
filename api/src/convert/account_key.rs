//! Convert to/from external::AccountKey

use crate::{external, ConversionError};
use mc_account_keys::AccountKey;
use mc_crypto_keys::{KeyError, RistrettoPrivate};

impl From<&AccountKey> for external::AccountKey {
    fn from(src: &AccountKey) -> Self {
        external::AccountKey {
            view_private_key: Some(src.view_private_key().into()),
            spend_private_key: Some(src.spend_private_key().into()),
            fog_report_url: src.fog_report_url().unwrap_or("").into(),
            fog_report_id: src.fog_report_id().unwrap_or("").into(),
            fog_authority_spki: src.fog_authority_spki().unwrap_or(&[]).to_vec(),
        }
    }
}

impl TryFrom<&external::AccountKey> for AccountKey {
    type Error = ConversionError;

    fn try_from(src: &external::AccountKey) -> Result<Self, Self::Error> {
        let spend_private_key = src
            .spend_private_key
            .as_ref()
            .ok_or(KeyError::LengthMismatch(0, 32))
            .and_then(|key| RistrettoPrivate::try_from(&key.data[..]))?;

        let view_private_key = src
            .view_private_key
            .as_ref()
            .ok_or(KeyError::LengthMismatch(0, 32))
            .and_then(|key| RistrettoPrivate::try_from(&key.data[..]))?;

        if src.fog_report_url.is_empty() {
            Ok(AccountKey::new(&spend_private_key, &view_private_key))
        } else {
            Ok(AccountKey::new_with_fog(
                &spend_private_key,
                &view_private_key,
                &src.fog_report_url,
                &src.fog_report_id,
                &src.fog_authority_spki[..],
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_util_serial::round_trip_message_and_conversion;
    use mc_util_test_helper::get_seeded_rng;

    // Test converting between external::AccountKey and account_keys::AccountKey
    #[test]
    fn test_account_key_conversion() {
        let mut rng = get_seeded_rng();

        // without fog_report_url
        round_trip_message_and_conversion::<AccountKey, external::AccountKey>(&AccountKey::random(
            &mut rng,
        ));

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
            round_trip_message_and_conversion::<AccountKey, external::AccountKey>(&account_key);
        }
    }
}
