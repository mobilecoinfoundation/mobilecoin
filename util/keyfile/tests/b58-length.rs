use mc_account_keys::{AccountKey, RootIdentity};
use mc_api::printable::PrintableWrapper;
use mc_util_test_helper::{run_with_several_seeds, CryptoRng, RngCore};

// The limit which we require b58 addresses to be less than
const B58_ADDRESS_LIMIT: usize = 255;
// The limit which we impose on fog domains like "fog.mobilecoin.com"
const DOMAIN_LIMIT: usize = 34;

// Try making a fog address with this domain length, (and an rng), several
// times. Return true if the b58 encoded public address sometimes matches or
// exceeds B58_ADDRESS_LIMIT
fn test_b58pub_length<T: RngCore + CryptoRng>(
    domain_length: usize,
    num_trials: usize,
    rng: &mut T,
) -> bool {
    let url = format!("fog://{}", "a".repeat(domain_length));
    for _ in 0..num_trials {
        let root_id = RootIdentity::random_with_fog(
            rng,
            &url,
            "",
            b"DEADBEEF", /* Length doesn't matter because fog authority spki is signed when we
                          * go to public address and signature has fixed
                          * length in the public address */
        );

        let acct_key = AccountKey::from(&root_id);
        let addr = acct_key.default_subaddress();

        let wrapper = PrintableWrapper::from(&addr);
        let data = wrapper.b58_encode().unwrap();

        if data.len() >= B58_ADDRESS_LIMIT {
            return true;
        }
    }
    false
}

#[test]
fn test_b58_pub_length() {
    run_with_several_seeds(|mut rng| {
        for domain_len in 0..DOMAIN_LIMIT {
            assert!(
                !test_b58pub_length(domain_len, 10, &mut rng),
                "B58 address limit exceeded for domain length = {}",
                domain_len
            );
        }

        assert!(test_b58pub_length(DOMAIN_LIMIT, 10, &mut rng), "Domain limit is not computed correctly, we didn't exceed the limit with urls of length {}", DOMAIN_LIMIT);
    })
}
