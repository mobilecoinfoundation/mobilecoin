use core::convert::TryFrom;
use mc_crypto_keys::RistrettoPrivate;
use mc_transaction_core::account_keys::{AccountKey, PublicAddress};
use mc_util_b58_payloads::payloads::RequestPayload;
use mc_util_from_random::FromRandom;
use mc_util_test_helper::SeedableRng;
use mc_util_url_encoding::{MobUrl, PaymentRequest};
use rand_hc::Hc128Rng;

fn sample_pub_addresses() -> Vec<PublicAddress> {
    let mut rng = Hc128Rng::from_seed([1u8; 32]);

    let accts = [
        AccountKey::new(
            &RistrettoPrivate::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
        ),
        AccountKey::new_with_fog(
            &RistrettoPrivate::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
            "fog://fog.mobilecoin.signal.org",
            "".to_string(),
            b"12345678",
        ),
        AccountKey::new_with_fog(
            &RistrettoPrivate::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
            "fog://fog.diogenes.mobilecoin.com",
            "".to_string(),
            b"99999999",
        ),
    ];

    accts.iter().map(|acct| acct.default_subaddress()).collect()
}

#[test]
fn test_url_encoding() {
    let addrs = sample_pub_addresses();

    {
        let addr = &addrs[0];
        let payload = PaymentRequest::from(addr);
        let encoded = MobUrl::try_from(&payload).unwrap();
        let encoded_str: &str = encoded.as_ref();
        assert_eq!("mob:///eCwRQ1riR1LTp8rpOMcn_rc3EajKx1EZ3cXV17SPDn2UyDJYXMl9TdQZoo5H3MDzTz14WBFVAARfGrXbMv8hG3Da", encoded_str);
        assert_eq!(95, encoded_str.len());

        let b58_payload = RequestPayload::new_v0(
            &addr.spend_public_key().to_bytes(),
            &addr.view_public_key().to_bytes(),
        )
        .unwrap();
        let b58_encoded = "mob:///".to_string() + &b58_payload.encode();
        assert_eq!("mob:///8BicLagkcC2AxG2foBd76LFAPNpLiwat5C6r57FHz3ddWiNCQYk4JEzpwvUd1NJbDeuPNCeM1gQMq8dyw1b72zkKpYqToWJW", b58_encoded);
        assert_eq!(103, b58_encoded.len());
    }

    {
        let addr = &addrs[1];
        let payload = PaymentRequest::from(addr);
        let encoded = MobUrl::try_from(&payload).unwrap();
        let encoded_str: &str = encoded.as_ref();
        assert_eq!("mob://fog.mobilecoin.signal.org/rmiEqq-34E3Fbm3hwxaYJtPZzu9THCBkQaqJDeZwuXG8mf2yOhmGoZmnKTu3--ZCj--5MdTwwCib2p7Dn3KTCl6E?s=KovIno-JXUsQuTSmUj4MDowMENWBpAbrHcT61x72MWNc24hBmdiRlPtpuxSdju_eaMXKeSrLLHjP7VltAuI_hP1f", encoded_str);
        assert_eq!(211, encoded_str.len());

        let b58_payload = RequestPayload::new_v1(
            &addr.spend_public_key().to_bytes(),
            &addr.view_public_key().to_bytes(),
            addr.fog_report_url().unwrap(),
            "",
            addr.fog_authority_sig().unwrap(),
        )
        .unwrap();
        let b58_encoded = "mob:///".to_string() + &b58_payload.encode();
        assert_eq!("mob:///49XpEmD6GpoQtxBRMwuUd5LWqaMFd939QPAh4EPw9rndk637NwBYY9LRvAWAEafeRoPoQ9ZFSC44Epo547c4gtnb9V2ouXLGYGm8uVS5EjYrMaCpTeP2DLaxiJsxHd2qFTJi1qbftNXfKf4nQNy1CtaTPDytvR1cFT58WcVGpyUPX1Qw3qf5nznBjxZUE3fCQcmZXbqvfie8xAjXRHaP5RBn7s7CQBRqgTnmSX", b58_encoded);
        assert_eq!(237, b58_encoded.len());
    }

    {
        let addr = &addrs[1];
        let payload = PaymentRequest {
            address: addr.clone(),
            amount: Some(666),
            memo: Some("2 baby goats".to_string()),
        };
        let encoded = MobUrl::try_from(&payload).unwrap();
        let encoded_str: &str = encoded.as_ref();
        assert_eq!("mob://fog.mobilecoin.signal.org/rmiEqq-34E3Fbm3hwxaYJtPZzu9THCBkQaqJDeZwuXG8mf2yOhmGoZmnKTu3--ZCj--5MdTwwCib2p7Dn3KTCl6E?a=666&m=2+baby+goats&s=KovIno-JXUsQuTSmUj4MDowMENWBpAbrHcT61x72MWNc24hBmdiRlPtpuxSdju_eaMXKeSrLLHjP7VltAuI_hP1f", encoded_str);
        assert_eq!(232, encoded_str.len());

        let b58_payload = RequestPayload::new_v3(
            &addr.spend_public_key().to_bytes(),
            &addr.view_public_key().to_bytes(),
            addr.fog_report_url().unwrap(),
            "",
            addr.fog_authority_sig().unwrap(),
            666,
            "2 baby goats",
        )
        .unwrap();
        let b58_encoded = "mob:///".to_string() + &b58_payload.encode();
        assert_eq!("mob:///2EdRJD64CAZ3T8QnbVT9fQe4BjmrKACEyzDmui5yWc2q3ZfjiCkusBn9kjFquJuDMJVJsYwqFGeXk8spmn33RFXyvGNTAZnTXA4AtjrYbx2kLkLySPi7tz17YSLtmpb5FGG9B3iGsA16SvKsiXj6dkvaHaddDKdHVrwo86uveUka36R2vaaTS4uzCxKnBPXwj7fB72dYY6yefjCZYGWAsqJbjNZ6tv8hvi8qB9tUYwKq21jHGyJQwaw63V1DWiXZCPk", b58_encoded);
        assert_eq!(266, b58_encoded.len());
    }

    {
        let addr = &addrs[2];
        let payload = PaymentRequest::from(addr);
        let encoded = MobUrl::try_from(&payload).unwrap();
        let encoded_str: &str = encoded.as_ref();
        assert_eq!("mob://fog.diogenes.mobilecoin.com/krmSAg7MnM0fn-yTIjV6tHtRA7Zj2JRZ4pJ-_PcweTkAu7afknATa5hFwtc_Zvi8R6d36cnpMA0-inMbZHiqMRqp?s=SC9cs96Ry9z4Js_VXkC35IMnTjpQCtEujN8D-R15qTsJloN2pZ75BbSzGtQJ99kBt8mM2YBhlTW9wuCfzHU3gJmx", encoded_str);

        let b58_payload = RequestPayload::new_v1(
            &addr.spend_public_key().to_bytes(),
            &addr.view_public_key().to_bytes(),
            addr.fog_report_url().unwrap(),
            "",
            addr.fog_authority_sig().unwrap(),
        )
        .unwrap();
        let b58_encoded = "mob:///".to_string() + &b58_payload.encode();
        assert_eq!("mob:///B5bnf3HTWMZLpvVse4aKVr3UWqZdV1FwHaUcx9wTVk5FqtAwKGQswhnZj5nFz8UmVNY1RSHsgYrfKWyf37rvg4eSBobaBryzo32i7k3ksi4wwiFRbdLhM2yECpGLMqox7YhWdLyGTHozgB1udkccUmjURQhy4h8ZdedtXntyNAidgbhUetYdawrygn6Y9JnwafZU8jyoKZj3kUAAs7xqy45BeBd41nXaQguz9X6P", b58_encoded);

        assert!(encoded_str.len() < b58_encoded.len());
    }

    {
        let addr = &addrs[2];
        let payload = PaymentRequest {
            address: addr.clone(),
            amount: Some(666),
            memo: Some("2 baby goats".to_string()),
        };
        let encoded = MobUrl::try_from(&payload).unwrap();
        let encoded_str: &str = encoded.as_ref();
        assert_eq!("mob://fog.diogenes.mobilecoin.com/krmSAg7MnM0fn-yTIjV6tHtRA7Zj2JRZ4pJ-_PcweTkAu7afknATa5hFwtc_Zvi8R6d36cnpMA0-inMbZHiqMRqp?a=666&m=2+baby+goats&s=SC9cs96Ry9z4Js_VXkC35IMnTjpQCtEujN8D-R15qTsJloN2pZ75BbSzGtQJ99kBt8mM2YBhlTW9wuCfzHU3gJmx", encoded_str);
        assert_eq!(234, encoded_str.len());

        let b58_payload = RequestPayload::new_v3(
            &addr.spend_public_key().to_bytes(),
            &addr.view_public_key().to_bytes(),
            addr.fog_report_url().unwrap(),
            "",
            addr.fog_authority_sig().unwrap(),
            666,
            "2 baby goats",
        )
        .unwrap();
        let b58_encoded = "mob:///".to_string() + &b58_payload.encode();
        assert_eq!("mob:///GTzg6TLXXx2WiSWBkSwH9KC5qof4R7iMZZvjhTPcT52wWDcoqxZhVFzBjUKi8t6m7TwyLRJWjq2jaLv58QJB6dfhZe1FLwzaMKYi8ibXqvCG6DEJ7YJXGUsL7RNN8ife3otBVaUReYaTMjHGihCpfppKGmHy2yzetAmwgPkqHkLQaTjGN12U8RU4n6gkNpawX87wBP9UZxA1zphZdRpSZwDNZJqSgmf4kcanY7sf6dVaqdTuVgBUuDRx93Nog9PK16NJW", b58_encoded);
        assert_eq!(268, b58_encoded.len());
    }
}
