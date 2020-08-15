use core::convert::TryFrom;
use mc_account_keys::{AccountKey, PublicAddress};
use mc_crypto_keys::RistrettoPrivate;
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
        let payload = PaymentRequest {
            address: addr.clone(),
            amount: Some(666),
            memo: Some("2 baby goats".to_string()),
        };
        let encoded = MobUrl::try_from(&payload).unwrap();
        let encoded_str: &str = encoded.as_ref();
        assert_eq!("mob://fog.mobilecoin.signal.org/rmiEqq-34E3Fbm3hwxaYJtPZzu9THCBkQaqJDeZwuXG8mf2yOhmGoZmnKTu3--ZCj--5MdTwwCib2p7Dn3KTCl6E?a=666&m=2+baby+goats&s=Ogw_pwCYvWIH4U3Fp_meqsRNIuRTM7t7dm2xPYTpSgkD3Slnk6cb-lCQRaZaEhu8dxyLQJ6VqoqvF-ZDjcMdhIP3", encoded_str);
        assert_eq!(232, encoded_str.len());

        let b58_payload = RequestPayload::new_v4(
            &addr.spend_public_key().to_bytes(),
            &addr.view_public_key().to_bytes(),
            addr.fog_report_url().unwrap(),
            666,
            "2 baby goats",
            "",
            addr.fog_authority_fingerprint_sig().unwrap(),
        )
        .unwrap();
        let b58_encoded = "mob:///".to_string() + &b58_payload.encode();
        assert_eq!("mob:///269zXNVHVYVq6Z9hrS1AmxtamM2X2gKoYeEafzdc2JrZN2pp8s5ZmKfrxaAffvT54hBufmF2GrGq267H1VLAo2LuiYiY97CEgKuM7DGrHngQrNKJMXfy1N8mETeco5p9p3QW2mXFiv9LfYGJfyK61PpRkoPwx1hBPFVuq6pDM2jNKR8JAoDyJkkCCW1Bsdy7hMAbkzZ5vZCwdqDp6GvPqaZ6vjumpkVat4RTHx13di4e5BmEpbGBCaeMp77QhKXoDxB", b58_encoded);
        assert_eq!(266, b58_encoded.len());
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
        assert_eq!("mob://fog.diogenes.mobilecoin.com/krmSAg7MnM0fn-yTIjV6tHtRA7Zj2JRZ4pJ-_PcweTkAu7afknATa5hFwtc_Zvi8R6d36cnpMA0-inMbZHiqMRqp?a=666&m=2+baby+goats&s=BvPCBBLW_PzgnuwvyXDl5OX7oj48ibwFCN5MfnZxKy3kXVD1uJyUv9DHA89euJeY6NnTauicxmKc98zNAiXVhlyC", encoded_str);
        assert_eq!(234, encoded_str.len());

        let b58_payload = RequestPayload::new_v4(
            &addr.spend_public_key().to_bytes(),
            &addr.view_public_key().to_bytes(),
            addr.fog_report_url().unwrap(),
            666,
            "2 baby goats",
            "",
            addr.fog_authority_fingerprint_sig().unwrap(),
        )
        .unwrap();
        let b58_encoded = "mob:///".to_string() + &b58_payload.encode();
        assert_eq!("mob:///A5kTrBAjEj2r72QnwJeQe6CXed6DLpUZuQZjVzoYfvuZKxgyn166FJiBehmyVGX1tVbunEyjdNHxCtpWPGnYkavryzigWg1VGAdyDLMVWnCgS9qcTjoSqwaNeMzyJqLwypkCA2GZaZGqE9wqGr4heiudKMrtzqfpKhKbzBvwkLPXBUh1qYvh8TsusayjPaJsa24nMEJaH49xp6Uzoes4En6CsYW6eeGfKLv9ZTMZDqybF7Tw9YViXAYHQ8KdQnjbGTu7M", b58_encoded);
        assert_eq!(268, b58_encoded.len());
    }
}
