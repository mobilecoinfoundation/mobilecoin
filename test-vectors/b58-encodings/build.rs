use mc_account_keys::{AccountKey, RootIdentity};
use mc_api::printable::PrintableWrapper;
use mc_test_vectors_definitions::b58_encodings::*;
use mc_util_test_vector::write_jsonl;
use std::convert::TryInto;

fn main() {
    write_jsonl("../vectors", || {
        (0..10)
            .map(|n| {
                let account_key = AccountKey::from(&RootIdentity::from(&[n; 32]));
                let public_address = account_key.default_subaddress();
                let mut wrapper = PrintableWrapper::new();
                wrapper.set_public_address((&public_address).try_into().unwrap());
                let b58_encoded = wrapper.b58_encode().unwrap();
                B58EncodePublicAddressWithoutFog {
                    view_public_key: public_address.view_public_key().to_bytes(),
                    spend_public_key: public_address.spend_public_key().to_bytes(),
                    b58_encoded,
                }
            })
            .collect::<Vec<_>>()
    })
    .expect("Unable to write test vectors");

    write_jsonl("../vectors", || {
        (0..10)
            .map(|n| {
                let account_key = AccountKey::from(&RootIdentity {
                    root_entropy: (&[n; 32]).into(),
                    fog_report_url: "fog://example.com".to_owned(),
                    fog_report_id: "".to_owned(),
                    fog_authority_spki: Vec::new(),
                });
                let public_address = account_key.default_subaddress();
                let mut wrapper = PrintableWrapper::new();
                wrapper.set_public_address((&public_address).try_into().unwrap());
                let b58_encoded = wrapper.b58_encode().unwrap();
                B58EncodePublicAddressWithFog {
                    view_public_key: public_address.view_public_key().to_bytes(),
                    spend_public_key: public_address.spend_public_key().to_bytes(),
                    fog_report_url: public_address.fog_report_url().unwrap_or("").to_owned(),
                    fog_report_id: public_address.fog_report_id().unwrap_or("").to_owned(),
                    fog_authority_sig: public_address.fog_authority_sig().unwrap_or(&[]).to_owned(),
                    b58_encoded,
                }
            })
            .collect::<Vec<_>>()
    })
    .expect("Unable to write test vectors");
}
