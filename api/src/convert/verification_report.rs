//! Convert to/from external::VerificationReport

use crate::external;
use mc_attest_core::{VerificationReport, VerificationSignature};
use protobuf::RepeatedField;

impl From<&VerificationReport> for external::VerificationReport {
    fn from(src: &VerificationReport) -> Self {
        let mut dst = external::VerificationReport::new();

        dst.set_sig(Vec::from(src.sig.as_ref()));
        dst.set_chain(RepeatedField::from_slice(&src.chain));
        dst.set_http_body(src.http_body.clone());
        dst
    }
}

impl From<&external::VerificationReport> for VerificationReport {
    fn from(src: &external::VerificationReport) -> Self {
        VerificationReport {
            sig: VerificationSignature::from(src.get_sig()),
            chain: src.get_chain().to_vec(),
            http_body: src.get_http_body().to_owned(),
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use rand::{rngs::StdRng, SeedableRng};
//
//     // Test converting between external::AccountKey and account_keys::AccountKey
//     #[test]
//     fn test_account_key_conversion() {
//         let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
//
//         // without fog_report_url
//         {
//             // account_keys -> external
//             let account_key = AccountKey::random(&mut rng);
//             let proto_credentials = external::AccountKey::from(&account_key);
//             assert_eq!(
//                 *proto_credentials.get_view_private_key(),
//                 external::RistrettoPrivate::from(account_key.view_private_key())
//             );
//             assert_eq!(
//                 *proto_credentials.get_spend_private_key(),
//                 external::RistrettoPrivate::from(account_key.spend_private_key())
//             );
//             assert_eq!(proto_credentials.fog_report_url, String::from(""));
//
//             assert_eq!(proto_credentials.fog_authority_spki.len(), 0);
//
//             assert_eq!(proto_credentials.fog_report_id, String::from(""));
//
//             // external -> account_keys
//             let account_key2 = AccountKey::try_from(&proto_credentials).unwrap();
//             assert_eq!(account_key, account_key2);
//         }
//
//         // with valid fog_report_url
//         {
//             // account_keys -> external
//             let tmp_account_key = AccountKey::random(&mut rng);
//             let account_key = AccountKey::new_with_fog(
//                 tmp_account_key.spend_private_key(),
//                 tmp_account_key.view_private_key(),
//                 "fog://test.mobilecoin.com".to_string(),
//                 "99".to_string(),
//                 vec![9, 9, 9, 9],
//             );
//
//             let proto_credentials = external::AccountKey::from(&account_key);
//             assert_eq!(
//                 *proto_credentials.get_view_private_key(),
//                 external::RistrettoPrivate::from(account_key.view_private_key())
//             );
//             assert_eq!(
//                 *proto_credentials.get_spend_private_key(),
//                 external::RistrettoPrivate::from(account_key.spend_private_key())
//             );
//             assert_eq!(
//                 proto_credentials.fog_report_url,
//                 String::from("fog://test.mobilecoin.com")
//             );
//
//             assert_eq!(proto_credentials.fog_authority_spki, vec![9, 9, 9, 9],);
//
//             assert_eq!(proto_credentials.fog_report_id, String::from("99"));
//
//             // external -> account_keys
//             let account_key2 = AccountKey::try_from(&proto_credentials).unwrap();
//             assert_eq!(account_key, account_key2);
//         }
//     }
// }
