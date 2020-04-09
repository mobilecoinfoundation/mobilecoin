// Copyright (c) 2018-2020 MobileCoin Inc.

use digestible::{Digest, Digestible};
use sha3::Sha3_256;

struct Foo {}

impl Digestible for Foo {
    fn digest<D: Digest>(&self, hasher: &mut D) {
        hasher.input(b"Moose");
    }
}

#[test]
fn test_digest_with() {
    assert_eq!(Foo {}.digest_with::<Sha3_256>(), Sha3_256::digest(b"Moose"));
}

// Test digesting of u64
#[test]
fn test_u64() {
    assert_eq!(
        u64::max_value().digest_with::<Sha3_256>(),
        Sha3_256::digest(&[255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8])
    );
    assert_eq!(
        (u32::max_value() as u64).digest_with::<Sha3_256>(),
        Sha3_256::digest(&[255u8, 255u8, 255u8, 255u8, 0u8, 0u8, 0u8, 0u8])
    );
}

// Test digesting of Option
#[test]
fn test_digest_option() {
    let temp: Option<u64> = None;
    assert_eq!(temp.digest_with::<Sha3_256>(), Sha3_256::digest(&[0u8]));
    let temp: Option<u64> = Some(u64::max_value());
    assert_eq!(
        temp.digest_with::<Sha3_256>(),
        Sha3_256::digest(&[1u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8])
    );
}
