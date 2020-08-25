// Copyright (c) 2018-2020 MobileCoin Inc.

/// Tests against the behavior of the generated Digestible traits
use generic_array::{typenum, GenericArray};
use mc_crypto_digestible::{Digest, Digestible};

// A struct implementing Digest that remembers all its historical inputs
#[derive(Clone, Default)]
struct Tester {
    pub args: Vec<Vec<u8>>,
}

impl Digest for Tester {
    type OutputSize = typenum::U1;

    fn new() -> Self {
        Default::default()
    }

    fn update(&mut self, src: impl AsRef<[u8]>) {
        self.args.push(src.as_ref().to_vec())
    }

    // Unused stuff
    fn chain(self, _src: impl AsRef<[u8]>) -> Self {
        unimplemented!()
    }
    fn finalize(self) -> GenericArray<u8, Self::OutputSize> {
        unimplemented!()
    }
    fn finalize_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        unimplemented!()
    }
    fn reset(&mut self) {}
    fn output_size() -> usize {
        unimplemented!()
    }
    fn digest(_data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        unimplemented!()
    }
}

// Test structs
#[derive(Digestible)]
struct Foo {
    a: u16,
    b: u16,
    c: u16,
}

#[derive(Digestible)]
struct Blob(Vec<u8>);

#[derive(Digestible)]
struct Bar {
    d: Blob,
    e: u32,
    f: Foo,
}

#[derive(Digestible)]
struct GenericFoo<X: Digestible> {
    a: X,
    b: X,
}

#[test]
fn foo1() {
    let arg = Foo { a: 0, b: 1, c: 2 };
    let mut hasher = Tester::new();
    arg.digest(&mut hasher);

    let expected: Vec<Vec<u8>> = vec![
        b"Foo".to_vec(),
        b"".to_vec(),
        b"a".to_vec(),
        vec![0u8, 0u8],
        b"b".to_vec(),
        vec![1u8, 0u8],
        b"c".to_vec(),
        vec![2u8, 0u8],
    ];

    assert_eq!(hasher.args, expected);
}

#[test]
fn blob1() {
    let arg = Blob(vec![1, 2, 3, 4]);
    let mut hasher = Tester::new();
    arg.digest(&mut hasher);

    let expected: Vec<Vec<u8>> = vec![
        b"Blob".to_vec(),
        b"".to_vec(),
        b"0".to_vec(),
        4usize.to_le_bytes().to_vec(),
        vec![1u8, 2u8, 3u8, 4u8],
    ];

    assert_eq!(hasher.args, expected);
}

#[test]
fn bar1() {
    let arg = Bar {
        d: Blob(b"Koala".to_vec()),
        e: u32::max_value(),
        f: Foo { a: 5, b: 6, c: 7 },
    };
    let mut hasher = Tester::new();
    arg.digest(&mut hasher);

    let expected: Vec<Vec<u8>> = vec![
        b"Bar".to_vec(),
        b"".to_vec(),
        b"d".to_vec(),
        b"Blob".to_vec(),
        b"".to_vec(),
        b"0".to_vec(),
        5usize.to_le_bytes().to_vec(),
        b"Koala".to_vec(),
        b"e".to_vec(),
        vec![255u8, 255u8, 255u8, 255u8],
        b"f".to_vec(),
        b"Foo".to_vec(),
        b"".to_vec(),
        b"a".to_vec(),
        vec![5u8, 0u8],
        b"b".to_vec(),
        vec![6u8, 0u8],
        b"c".to_vec(),
        vec![7u8, 0u8],
    ];

    assert_eq!(hasher.args, expected);
}

#[test]
fn generic_foo1() {
    let arg = GenericFoo {
        a: 123 as u32,
        b: 456 as u32,
    };

    let mut hasher = Tester::new();
    arg.digest(&mut hasher);

    let expected: Vec<Vec<u8>> = vec![
        b"GenericFoo".to_vec(),
        b"< X : Digestible >".to_vec(),
        b"u32".to_vec(),
        b"a".to_vec(),
        (123 as u32).to_le_bytes().to_vec(),
        b"b".to_vec(),
        (456 as u32).to_le_bytes().to_vec(),
    ];

    assert_eq!(hasher.args, expected);
}

#[test]
fn generic_foo2() {
    let arg = GenericFoo {
        a: String::from("str1"),
        b: String::from("str2"),
    };

    let mut hasher = Tester::new();
    arg.digest(&mut hasher);

    let expected: Vec<Vec<u8>> = vec![
        b"GenericFoo".to_vec(),
        b"< X : Digestible >".to_vec(),
        b"alloc::string::String".to_vec(),
        b"a".to_vec(),
        (4 as usize).to_le_bytes().to_vec(),
        b"str1".to_vec(),
        b"b".to_vec(),
        (4 as usize).to_le_bytes().to_vec(),
        b"str2".to_vec(),
    ];

    assert_eq!(hasher.args, expected);
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

        let expected: Vec<Vec<u8>> = vec![
            b"TestEnum".to_vec(),
            b"< V : Digestible >".to_vec(),
            b"u64".to_vec(),
            (0 as u64).to_le_bytes().to_vec(),
            b"Option1".to_vec(),
        ];

        let mut hasher = Tester::new();
        obj.digest(&mut hasher);
        assert_eq!(hasher.args, expected);
    }

    {
        let obj = TestEnum::<u64>::Option2(123);

        let expected: Vec<Vec<u8>> = vec![
            b"TestEnum".to_vec(),
            b"< V : Digestible >".to_vec(),
            b"u64".to_vec(),
            (1 as u64).to_le_bytes().to_vec(),
            b"Option2".to_vec(),
            b"0".to_vec(),
            (123 as u64).to_le_bytes().to_vec(),
        ];

        let mut hasher = Tester::new();
        obj.digest(&mut hasher);
        assert_eq!(hasher.args, expected);
    }

    {
        let s: &str = "a string";
        let obj = TestEnum::<u64>::Option3(1234, s.to_owned());

        let expected: Vec<Vec<u8>> = vec![
            b"TestEnum".to_vec(),
            b"< V : Digestible >".to_vec(),
            b"u64".to_vec(),
            (2 as u64).to_le_bytes().to_vec(),
            b"Option3".to_vec(),
            b"0".to_vec(),
            (1234 as u32).to_le_bytes().to_vec(),
            b"1".to_vec(),
            s.len().to_le_bytes().to_vec(),
            s.as_bytes().to_vec(),
        ];

        let mut hasher = Tester::new();
        obj.digest(&mut hasher);
        assert_eq!(hasher.args, expected);
    }

    {
        let obj = TestEnum::<u64>::Option4 { a: 123, b: 456 };

        let expected: Vec<Vec<u8>> = vec![
            b"TestEnum".to_vec(),
            b"< V : Digestible >".to_vec(),
            b"u64".to_vec(),
            (3 as u64).to_le_bytes().to_vec(),
            b"Option4".to_vec(),
            b"a".to_vec(),
            (123 as u64).to_le_bytes().to_vec(),
            b"b".to_vec(),
            (456 as u64).to_le_bytes().to_vec(),
        ];

        let mut hasher = Tester::new();
        obj.digest(&mut hasher);
        assert_eq!(hasher.args, expected);
    }
}
