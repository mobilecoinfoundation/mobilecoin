use crate::{Error, MobUrl};
use core::convert::TryFrom;
use mc_account_keys::PublicAddress;

/// A payment request, containing a public address, and optionally an amount
/// and memo.
/// This can be encoded as a MobUrl and a MobUrl can be constructed from this.
/// To add more optional fields, designate query parameters for them in MobUrl
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentRequest {
    /// The public address included in the request
    pub address: PublicAddress,
    /// The amount included in the request, if any
    pub amount: Option<u64>,
    /// The memo included in the request, if any
    pub memo: Option<String>,
}

impl From<&PublicAddress> for PaymentRequest {
    fn from(src: &PublicAddress) -> PaymentRequest {
        PaymentRequest {
            address: src.clone(),
            amount: None,
            memo: None,
        }
    }
}

impl TryFrom<&PaymentRequest> for MobUrl {
    type Error = Error;
    fn try_from(src: &PaymentRequest) -> Result<MobUrl, Error> {
        let mut result = MobUrl::try_from(&src.address)?;
        if let Some(amount) = src.amount.as_ref() {
            result.set_amount(*amount);
        }
        if let Some(memo) = src.memo.as_ref() {
            result.set_memo(memo);
        }
        Ok(result)
    }
}

impl TryFrom<&MobUrl> for PaymentRequest {
    type Error = Error;
    fn try_from(src: &MobUrl) -> Result<PaymentRequest, Error> {
        let mut payload = PaymentRequest {
            address: PublicAddress::try_from(src)?,
            amount: None,
            memo: None,
        };

        if let Some(amount_str) = src.get_amount() {
            payload.amount = Some(amount_str.parse::<u64>().map_err(Error::Amount)?);
        }

        if let Some(memo_str) = src.get_memo() {
            payload.memo = Some(memo_str);
        }

        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::{MobUrl, PaymentRequest};

    use core::{convert::TryFrom, str::FromStr};

    use mc_account_keys::{AccountKey, RootEntropy, RootIdentity};
    use mc_crypto_keys::RistrettoPrivate;
    use mc_util_test_helper::{run_with_several_seeds, RngCore};

    // Test an example public address being parsed to mob url
    #[test]
    fn example_fog_public_address() {
        let identity = RootIdentity {
            root_entropy: RootEntropy::from(&[0u8; 32]),
            fog_report_url: "fog://example.com".to_owned(),
            fog_report_id: Default::default(),
            fog_authority_fingerprint: Default::default(),
        };

        let acct = AccountKey::from(&identity);

        let addr = acct.default_subaddress();

        let payload = PaymentRequest::from(&addr);

        let mob_url = MobUrl::try_from(&payload)
            .map_err(|err| {
                panic!("Error when decoding payload {:?}: {}", payload, err);
            })
            .unwrap();

        assert_eq!(mob_url.as_ref(), "mob://example.com/9i_xwzoihbGu5hLthygfLGi7K1sPFDmhPkq3KPmO-2p4kBwRg06ELfa-mMEnlTUT4RYJXUEizCfYB7RRHLgeEWfP?s=QqLfvkgCM29apl9PBGhIag-XlF-qy_CF2_qb7znsWhFViPW0f5v-ggZnCm0vkK5aaWAfP4uxWb5lWUa8zBpNjT9A");

        let payload2 = PaymentRequest::try_from(&mob_url).unwrap();

        assert_eq!(payload, payload2);
    }

    // Test an example fogless public address being parsed to mob url
    #[test]
    fn example_fogless_public_address() {
        let identity = RootIdentity::from(&RootEntropy::from(&[0u8; 32]));

        let acct = AccountKey::from(&identity);

        let addr = acct.default_subaddress();

        let payload = PaymentRequest::from(&addr);

        let mob_url = MobUrl::try_from(&payload)
            .map_err(|err| {
                panic!("Error when decoding payload {:?}: {}", payload, err);
            })
            .unwrap();

        assert_eq!(mob_url.as_ref(), "mob:///9i_xwzoihbGu5hLthygfLGi7K1sPFDmhPkq3KPmO-2p4kBwRg06ELfa-mMEnlTUT4RYJXUEizCfYB7RRHLgeEWfP");

        let payload2 = PaymentRequest::try_from(&mob_url).unwrap();

        assert_eq!(payload, payload2);
    }

    // Test an example request payload being parsed to mob url
    #[test]
    fn example_fog_payload() {
        let acct = AccountKey::new_with_fog(
            &RistrettoPrivate::try_from(&[0u8; 32]).unwrap(),
            &RistrettoPrivate::try_from(&[1u8; 32]).unwrap(),
            "fog://fog.mobilecoin.com".to_string(),
            0.to_string(),
            b"deadbeef".to_vec(),
        );

        let addr = acct.default_subaddress();

        let mut payload = PaymentRequest::from(&addr);

        payload.amount = Some(777);
        payload.memo = Some("2 baby goats".to_owned());

        let mob_url = MobUrl::try_from(&payload)
            .map_err(|err| {
                panic!("Error when decoding payload {:?}: {}", payload, err);
            })
            .unwrap();

        assert_eq!(mob_url.as_ref(), "mob://fog.mobilecoin.com/oGbA6juTWhUdfL6qNMocAGN96wNiZpZegP0TUjKXHEM-GYmM50bLJVeL6NgftIumjt8nwYw7MjEnQT7hCw9bVUgh?a=777&m=2+baby+goats&s=-ry4OlNUCMW1o8tZ188x4I8ppwTPik7t5jRxALmGDhB6hbitNs5Wx5W9go-BPkyieM_NbFVAlP848faDVXEFjAm1#0");

        let payload2 = PaymentRequest::try_from(&mob_url).unwrap();

        assert_eq!(payload, payload2);
    }

    // Test an example unicode request payload being parsed to mob url
    #[test]
    fn example_unicode_fog_payload() {
        let acct = AccountKey::new_with_fog(
            &RistrettoPrivate::try_from(&[0u8; 32]).unwrap(),
            &RistrettoPrivate::try_from(&[1u8; 32]).unwrap(),
            "fog://fog.mobilecoin.com".to_string(),
            0.to_string(),
            b"deadbeef".to_vec(),
        );

        let addr = acct.default_subaddress();

        let mut payload = PaymentRequest::from(&addr);

        payload.amount = Some(777);
        payload.memo = Some("لسلام عليكم".to_owned());

        let mob_url = MobUrl::try_from(&payload)
            .map_err(|err| {
                panic!("Error when decoding payload {:?}: {}", payload, err);
            })
            .unwrap();

        assert_eq!(mob_url.as_ref(), "mob://fog.mobilecoin.com/oGbA6juTWhUdfL6qNMocAGN96wNiZpZegP0TUjKXHEM-GYmM50bLJVeL6NgftIumjt8nwYw7MjEnQT7hCw9bVUgh?a=777&m=%D9%84%D8%B3%D9%84%D8%A7%D9%85+%D8%B9%D9%84%D9%8A%D9%83%D9%85&s=-ry4OlNUCMW1o8tZ188x4I8ppwTPik7t5jRxALmGDhB6hbitNs5Wx5W9go-BPkyieM_NbFVAlP848faDVXEFjAm1#0");

        let payload2 = PaymentRequest::try_from(&mob_url).unwrap();

        assert_eq!(payload, payload2);
    }

    // Test an example unicode request payload being parsed to mob url
    #[test]
    fn roundtrip_example_fog_payload_unicode() {
        for memo in &[
            String::from("السلام عليكم"),
            String::from("Dobrý den"),
            String::from("Hello"),
            String::from("שָׁלוֹם"),
            String::from("नमस्ते"),
            String::from("こんにちは"),
            String::from("안녕하세요"),
            String::from("你好"),
            String::from("Olá"),
            String::from("Здравствуйте"),
            String::from("Hola"),
        ] {
            let acct = AccountKey::new_with_fog(
                &RistrettoPrivate::try_from(&[0u8; 32]).unwrap(),
                &RistrettoPrivate::try_from(&[1u8; 32]).unwrap(),
                "fog://fog.mobilecoin.com".to_string(),
                0.to_string(),
                b"deadbeef".to_vec(),
            );

            let addr = acct.default_subaddress();

            let mut payload = PaymentRequest::from(&addr);

            payload.amount = Some(777);
            payload.memo = Some(memo.to_owned());

            let mob_url = MobUrl::try_from(&payload)
                .map_err(|err| {
                    panic!("Error when decoding payload {:?}: {}", payload, err);
                })
                .unwrap();

            let payload2 = PaymentRequest::try_from(&mob_url).unwrap();

            assert_eq!(payload, payload2);
        }
    }

    // Test an example fogless request payload being parsed to mob url
    #[test]
    fn example_fogless_payload() {
        let acct = AccountKey::new(
            &RistrettoPrivate::try_from(&[0u8; 32]).unwrap(),
            &RistrettoPrivate::try_from(&[1u8; 32]).unwrap(),
        );

        let addr = acct.default_subaddress();

        let mut payload = PaymentRequest::from(&addr);

        payload.amount = Some(777);
        payload.memo = Some("ham sandwich".to_owned());

        let mob_url = MobUrl::try_from(&payload)
            .map_err(|err| {
                panic!("Error when decoding payload {:?}: {}", payload, err);
            })
            .unwrap();

        assert_eq!(mob_url.as_ref(), "mob:///oGbA6juTWhUdfL6qNMocAGN96wNiZpZegP0TUjKXHEM-GYmM50bLJVeL6NgftIumjt8nwYw7MjEnQT7hCw9bVUgh?a=777&m=ham+sandwich");

        let payload2 = PaymentRequest::try_from(&mob_url).unwrap();

        assert_eq!(payload, payload2);
    }

    // Round trip random fog-less public address through mob url
    #[test]
    fn round_trip_random_public_address() {
        run_with_several_seeds(|mut rng| {
            let acct = AccountKey::random(&mut rng);

            let addr = acct.default_subaddress();

            let payload = PaymentRequest::from(&addr);

            let mob_url = MobUrl::try_from(&payload).expect("MobUrl from payload");

            let string_repr = mob_url.to_string();

            let mob_url2 = MobUrl::from_str(&string_repr).expect("MobUrl from str");

            assert_eq!(mob_url, mob_url2);

            let payload2 = PaymentRequest::try_from(&mob_url2).unwrap();

            assert_eq!(payload, payload2);

            let addr2 = payload2.address.clone();

            assert_eq!(addr, addr2);
        })
    }

    // Round trip random fog-less payloads through mob url
    #[test]
    fn round_trip_random_payload() {
        run_with_several_seeds(|mut rng| {
            let acct = AccountKey::random(&mut rng);

            let addr = acct.default_subaddress();

            let mut payload = PaymentRequest::from(&addr);

            payload.amount = Some(rng.next_u64());
            payload.memo = Some(rng.next_u64().to_string());

            let mob_url = MobUrl::try_from(&payload).expect("MobUrl from payload");

            let string_repr = mob_url.to_string();

            let mob_url2 = MobUrl::from_str(&string_repr).unwrap();

            assert_eq!(mob_url, mob_url2);

            let payload2 = PaymentRequest::try_from(&mob_url2).unwrap();

            assert_eq!(payload, payload2);

            let addr2 = payload2.address.clone();

            assert_eq!(addr, addr2);
        })
    }

    // Round trip random addresses with fog through mob url
    #[test]
    fn round_trip_random_fog_address() {
        run_with_several_seeds(|mut rng| {
            let acct = AccountKey::random_with_fog(&mut rng);

            let addr = acct.default_subaddress();

            let payload = PaymentRequest::from(&addr);

            let mob_url = MobUrl::try_from(&payload).expect("MobUrl from payload");

            let string_repr = mob_url.to_string();

            let mob_url2 = MobUrl::from_str(&string_repr).expect("MobUrl from str");

            assert_eq!(mob_url, mob_url2);

            let payload2 = PaymentRequest::try_from(&mob_url2).unwrap();

            assert_eq!(payload, payload2);

            let addr2 = payload2.address.clone();

            assert_eq!(addr, addr2);
        })
    }

    // Round trip random fog payloads through mob url
    #[test]
    fn round_trip_random_fog_payload() {
        run_with_several_seeds(|mut rng| {
            let acct = AccountKey::random_with_fog(&mut rng);

            let addr = acct.default_subaddress();

            let mut payload = PaymentRequest::from(&addr);

            payload.amount = Some(rng.next_u64());
            payload.memo = Some(rng.next_u64().to_string());

            let mob_url = MobUrl::try_from(&payload).unwrap();

            let string_repr = mob_url.to_string();

            let mob_url2 = MobUrl::from_str(&string_repr).unwrap();

            assert_eq!(mob_url, mob_url2);

            let payload2 = PaymentRequest::try_from(&mob_url2).unwrap();

            assert_eq!(payload, payload2);

            let addr2 = payload2.address.clone();

            assert_eq!(addr, addr2);
        })
    }
}
