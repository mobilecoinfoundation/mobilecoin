// Copyright (c) 2018-2020 MobileCoin Inc.

use mc_crypto_digestible::{Digest, Digestible};
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

// Test digesting an enum.
#[test]
fn test_digest_enum() {
    #[derive(Digestible)]
    enum TestEnum<V: Digestible> {
        Option1,
        Option2(V),
        Option3(u32, String),
        Option4 { a: V, b: V },
    }

    {
        let obj = TestEnum::<u64>::Option1;

        let mut expected_digest = Sha3_256::new();
        expected_digest.input("TestEnum");
        expected_digest.input("< V : Digestible >");
        expected_digest.input(&(0 as u64).to_le_bytes());
        expected_digest.input("Option1");
        assert_eq!(obj.digest_with::<Sha3_256>(), expected_digest.result());
    }

    {
        let obj = TestEnum::<u64>::Option2(123);

        let mut expected_digest = Sha3_256::new();
        expected_digest.input("TestEnum");
        expected_digest.input("< V : Digestible >");
        expected_digest.input(&(1 as u64).to_le_bytes());
        expected_digest.input("Option2");
        expected_digest.input("0");
        expected_digest.input((123 as u64).to_le_bytes());
        assert_eq!(obj.digest_with::<Sha3_256>(), expected_digest.result());
    }

    {
        let s: &str = "a string";
        let obj = TestEnum::<u64>::Option3(1234, s.to_owned());

        let mut expected_digest = Sha3_256::new();
        expected_digest.input("TestEnum");
        expected_digest.input("< V : Digestible >");
        expected_digest.input(&(2 as u64).to_le_bytes());
        expected_digest.input("Option3");
        expected_digest.input("0");
        expected_digest.input((1234 as u32).to_le_bytes());
        expected_digest.input("1");
        expected_digest.input(s.len().to_le_bytes());
        expected_digest.input(s);
        assert_eq!(obj.digest_with::<Sha3_256>(), expected_digest.result());
    }

    {
        let obj = TestEnum::<u64>::Option4 { a: 123, b: 456 };

        let mut expected_digest = Sha3_256::new();
        expected_digest.input("TestEnum");
        expected_digest.input("< V : Digestible >");
        expected_digest.input(&(3 as u64).to_le_bytes());
        expected_digest.input("Option4");
        expected_digest.input("a");
        expected_digest.input((123 as u64).to_le_bytes());
        expected_digest.input("b");
        expected_digest.input((456 as u64).to_le_bytes());
        assert_eq!(obj.digest_with::<Sha3_256>(), expected_digest.result());
    }
}
