// Copyright (c) 2018-2021 The MobileCoin Foundation

//! SLIP-0010 : Universal private key derivation from master private key.
//! https://github.com/satoshilabs/slips/blob/master/slip-0010.md
//!
//! Only ED25519 private key derivation is currently implemented.

use hmac::{Hmac, Mac, NewMac};

/// Derives only the private key for ED25519 in the manor defined in
/// [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md).
///
/// # Arguments
/// * `seed` - Seed, the BIP0039 output.
/// * `indexes` - an array of indexes that define the path. E.g. for m/1'/2'/3', pass 1, 2, 3.
///               As with Ed25519 non-hardened child indexes are not supported, this function treats all indexes
///                    as hardened.
///
/// # Examples
///
/// ```
/// use hex::ToHex;
/// use mc_util_slip10::derive_ed25519_private_key;
///
/// let seed = hex::decode("34e52ea12212a4b6ce7301eba2cbd9c089886ffb2af0c8835cd565106039a28d0319351451f493e4e9472f77d7ce4d910d552c5c4987e9600c5c436a93f59a24").unwrap();
/// let derived = derive_ed25519_private_key(&seed, &vec!(44, 511, 0));
///
/// assert_eq!("0c3cbb5de538596fbe0da4990a7ce5aa1db5eefecaff389b5ff83e5ad3033e09", derived.encode_hex::<String>());
///
/// ```
#[allow(non_snake_case)]
pub fn derive_ed25519_private_key(seed: &[u8], indexes: &[u32]) -> [u8; 32] {
    let mut I = hmac_sha512(b"ed25519 seed", &seed);
    let mut data = [0u8; 37];

    for i in indexes {
        let hardened_index = 0x80000000 | *i;
        let Il = &I[0..32];
        let Ir = &I[32..64];

        data[1..33].copy_from_slice(Il);
        data[33..37].copy_from_slice(&hardened_index.to_be_bytes());

        //I = HMAC-SHA512(Key = Ir, Data = 0x00 || Il || ser32(i'))
        I = hmac_sha512(&Ir, &data);
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&I[0..32]);
    result
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac =
        Hmac::<sha2::Sha512>::new_varkey(key).expect("hnew_varkey has no key size restrictions");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();

    let mut ret = [0; 64];
    assert_eq!(ret.len(), bytes.len());
    ret.copy_from_slice(bytes.as_slice());
    ret
}

/// Test cases from SLIP-0010 https://github.com/satoshilabs/slips/blob/master/slip-0010.md
/// Just relevant cases, Ed25519, private key
#[cfg(test)]
mod test {
    use super::*;
    use hex::ToHex;

    const CASE_1_SEED: &str = "000102030405060708090a0b0c0d0e0f";

    #[test]
    fn case1_m() {
        assert_eq!(
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
            derive_ed25519_private_key_hex(CASE_1_SEED, &vec!())
        );
    }

    #[test]
    fn case1_m_0h() {
        assert_eq!(
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
            derive_ed25519_private_key_hex(CASE_1_SEED, &vec!(0))
        );
    }

    #[test]
    fn case1_m_0h_1h() {
        assert_eq!(
            "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
            derive_ed25519_private_key_hex(CASE_1_SEED, &vec!(0, 1))
        );
    }

    #[test]
    fn case1_m_0h_1h_2h() {
        assert_eq!(
            "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
            derive_ed25519_private_key_hex(CASE_1_SEED, &vec!(0, 1, 2))
        );
    }

    #[test]
    fn case1_m_0h_1h_2h_2h() {
        assert_eq!(
            "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
            derive_ed25519_private_key_hex(CASE_1_SEED, &vec!(0, 1, 2, 2))
        );
    }

    #[test]
    fn case1_m_0h_1h_2h_1000000000h() {
        assert_eq!(
            "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
            derive_ed25519_private_key_hex(CASE_1_SEED, &vec!(0, 1, 2, 2, 1000000000))
        );
    }

    #[test]
    fn case1_m_0h_already_hardened() {
        assert_eq!(
            derive_ed25519_private_key_hex(CASE_1_SEED, &vec!(0)),
            derive_ed25519_private_key_hex(CASE_1_SEED, &vec!(0x80000000))
        );
    }

    #[test]
    fn case1_m_0h_1h_already_hardened() {
        assert_eq!(
            derive_ed25519_private_key_hex(CASE_1_SEED, &vec!(1)),
            derive_ed25519_private_key_hex(CASE_1_SEED, &vec!(0x80000001))
        );
    }

    const CASE_2_SEED: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

    #[test]
    fn case2_m() {
        assert_eq!(
            "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
            derive_ed25519_private_key_hex(CASE_2_SEED, &vec!())
        );
    }

    #[test]
    fn case2_m_0h() {
        assert_eq!(
            "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
            derive_ed25519_private_key_hex(CASE_2_SEED, &vec!(0))
        );
    }

    #[test]
    fn case2_m_0h_2147483647h() {
        assert_eq!(
            "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
            derive_ed25519_private_key_hex(CASE_2_SEED, &vec!(0, 2147483647))
        );
    }

    #[test]
    fn case2_m_0h_2147483647h_1h() {
        assert_eq!(
            "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
            derive_ed25519_private_key_hex(CASE_2_SEED, &vec!(0, 2147483647, 1))
        );
    }

    #[test]
    fn case2_m_0h_2147483647h_1h_2147483646h() {
        assert_eq!(
            "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
            derive_ed25519_private_key_hex(CASE_2_SEED, &vec!(0, 2147483647, 1, 2147483646))
        );
    }

    #[test]
    fn case2_m_0h_2147483647h_1h_2147483646h_2h() {
        assert_eq!(
            "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
            derive_ed25519_private_key_hex(CASE_2_SEED, &vec!(0, 2147483647, 1, 2147483646, 2))
        );
    }

    fn derive_ed25519_private_key_hex(seed_hex: &str, indexes: &[u32]) -> String {
        let seed = hex::decode(seed_hex).unwrap();

        let private_key = derive_ed25519_private_key(&seed, indexes);

        return private_key.encode_hex::<String>();
    }
}
