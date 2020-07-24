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
        assert_eq!("mob://fog.mobilecoin.signal.org/rmiEqq-34E3Fbm3hwxaYJtPZzu9THCBkQaqJDeZwuXG8mf2yOhmGoZmnKTu3--ZCj--5MdTwwCib2p7Dn3KTCl6E?a=666&m=2+baby+goats&s=KovIno-JXUsQuTSmUj4MDowMENWBpAbrHcT61x72MWNc24hBmdiRlPtpuxSdju_eaMXKeSrLLHjP7VltAuI_hP1f", encoded_str);
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
        assert_eq!("mob:///CzpFtx52f77AfogondLHGH4ZnhraB4igZKptek36H2mUPmj3qtLCV4UWB8QaDUqro3xBoKb4rXDSBm2nxV6GNz6pNfG5nwrdG17pPACnuh1NNFxyyUyEL6ckUfUhEYvPXLAy3JZhWCyi6g1S5MQd4NvaPXcptK14T5X2NP1yQei4paCBty8JxM4sc8mJa34NXYSySTnqAR53qC2WzmVKWtfuAAQXZU2jPR1kxZ2tJCdhBtERcfzsjKUAwZZMAYfgP9", b58_encoded);
        assert_eq!(265, b58_encoded.len());
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
        assert_eq!("mob:///8dUCXPapoK52Zvhdfb3YHpKJRDPKvXAJmeKjkAxXv7o4QDftDV2JPybwQXzzuU5pqqS3QJkGFnFVWzxDNdd86vEDm3HDdHSgjjX2b2dxW9PDP9Ly3ziqLsLvy1d9xpdVUGAo6gniDHbjNypcVXwyU7hQUmbuHK8YsfJkKz2DPj8GxT5dgMhNzgbmzenpoexERAc1NehdHpwi6e6Tro63i6ny7akE2911sxb8Ar12Lgk44Zsfvf43oRtQVmGGpWR5idGb1", b58_encoded);
        assert_eq!(268, b58_encoded.len());
    }
}
