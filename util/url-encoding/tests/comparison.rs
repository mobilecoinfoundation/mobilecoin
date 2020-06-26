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
        assert_eq!("mob:///eCwRQ1riR1LTp8rpOMcn_rc3EajKx1EZ3cXV17SPDn2UyDJYXMl9TdQZoo5H3MDzTz14WBFVAARfGrXbMv8hGw==?", encoded_str);
        assert_eq!(96, encoded_str.len());

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
        assert_eq!("mob://fog.mobilecoin.signal.org/rmiEqq-34E3Fbm3hwxaYJtPZzu9THCBkQaqJDeZwuXG8mf2yOhmGoZmnKTu3--ZCj--5MdTwwCib2p7Dn3KTCg==?s=CQkJCQ%3D%3D", encoded_str);
        assert_eq!(135, encoded_str.len());

        let b58_payload = RequestPayload::new_v1(
            &addr.spend_public_key().to_bytes(),
            &addr.view_public_key().to_bytes(),
            addr.fog_report_url().unwrap(),
            "",
            addr.fog_authority_sig().unwrap(),
        )
        .unwrap();
        let b58_encoded = "mob:///".to_string() + &b58_payload.encode();
        assert_eq!("mob:///5PFsXuSi9PUaJueuB4KxgWYiLXdL6EyvLmFGYiJ4Y5eGNJjHcZUraPTT1jTFd5QR7TXCTyYt5cLLxntmnvQnvr2Xq6czwZwGBMuhPEX6yoBFY2D1CeqGhQrmqcCGVm6y3abyVAL6rfrhbfe5SyBM", b58_encoded);
        assert_eq!(155, b58_encoded.len());
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
        assert_eq!("mob://fog.mobilecoin.signal.org/rmiEqq-34E3Fbm3hwxaYJtPZzu9THCBkQaqJDeZwuXG8mf2yOhmGoZmnKTu3--ZCj--5MdTwwCib2p7Dn3KTCg==?s=CQkJCQ%3D%3D&a=666&m=2+baby+goats", encoded_str);
        assert_eq!(156, encoded_str.len());

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
        assert_eq!("mob:///2iXQ1GUJPLuKZvKhGeCMDQdM4VsMvGNK3tVm7Kf68Hohf7Yhz6zigcDrh9x43PudHp4y5L5djNSy4rKRJtmEV8mHYm7Nt6b8p1NuNjZqV72qtru1uDgVgzmSqXAYS8wgXteqQBqnvQwE71ZranhPcCL1of38Tgz4J3z8Hc8ckjBmH9cnN", b58_encoded);
        assert_eq!(184, b58_encoded.len());
    }

    {
        let addr = &addrs[2];
        let payload = PaymentRequest::from(addr);
        let encoded = MobUrl::try_from(&payload).unwrap();
        let encoded_str: &str = encoded.as_ref();
        assert_eq!("mob://fog.diogenes.mobilecoin.com/krmSAg7MnM0fn-yTIjV6tHtRA7Zj2JRZ4pJ-_PcweTkAu7afknATa5hFwtc_Zvi8R6d36cnpMA0-inMbZHiqMQ==?s=CQkJCQ%3D%3D", encoded_str);

        let b58_payload = RequestPayload::new_v1(
            &addr.spend_public_key().to_bytes(),
            &addr.view_public_key().to_bytes(),
            addr.fog_report_url().unwrap(),
            "",
            addr.fog_authority_sig().unwrap(),
        )
        .unwrap();
        let b58_encoded = "mob:///".to_string() + &b58_payload.encode();
        assert_eq!("mob:///2M12NoHpvM5XMLtr4DYvdDvt9wUv1AsC2BbxCQD9ZsdanGbCA1V1wpXszfyYXh3Hr7f3RqzX3xZ1vtFJTkdinGYqJZCCbT8NqpEDk8S79ifZwgjjqZ63xzP4jH2rcgbLK9q1u2TdS1DyuwpH1857LHd", b58_encoded);

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
        assert_eq!("mob://fog.diogenes.mobilecoin.com/krmSAg7MnM0fn-yTIjV6tHtRA7Zj2JRZ4pJ-_PcweTkAu7afknATa5hFwtc_Zvi8R6d36cnpMA0-inMbZHiqMQ==?s=CQkJCQ%3D%3D&a=666&m=2+baby+goats", encoded_str);
        assert_eq!(158, encoded_str.len());

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
        assert_eq!("mob:///SaxbkSaDTRXWa6r5Ccfpu5FpHp8JwHtvXbwyvNbGde4YioYMWAJnT3zJZVCxGYvjWdZmBv37EMVFuJjYycKwqyV9J7MjfzYDZgiMYzzBmM74pJZs7cDD92b3Dj613AkKVgsbRCJ1tcj7zLzwVtMoocra7evyxRVHJgwiasazJV5Jgxwan5G", b58_encoded);
        assert_eq!(186, b58_encoded.len());
    }
}
