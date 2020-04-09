// Copyright (c) 2018-2020 MobileCoin Inc.

use digestible::{Digest, Digestible};
/// Tests against the behavior of the generated Digestible traits
use generic_array::{typenum, GenericArray};

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

    fn input<B: AsRef<[u8]>>(&mut self, src: B) {
        self.args.push(src.as_ref().to_vec())
    }

    // Unused stuff
    fn chain<B: AsRef<[u8]>>(self, _src: B) -> Self {
        unimplemented!()
    }
    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        unimplemented!()
    }
    fn result_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
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

#[test]
fn foo1() {
    let arg = Foo { a: 0, b: 1, c: 2 };
    let mut hasher = Tester::new();
    arg.digest(&mut hasher);

    let expected: Vec<Vec<u8>> = vec![
        b"Foo".to_vec(),
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
        b"d".to_vec(),
        b"Blob".to_vec(),
        b"0".to_vec(),
        5usize.to_le_bytes().to_vec(),
        b"Koala".to_vec(),
        b"e".to_vec(),
        vec![255u8, 255u8, 255u8, 255u8],
        b"f".to_vec(),
        b"Foo".to_vec(),
        b"a".to_vec(),
        vec![5u8, 0u8],
        b"b".to_vec(),
        vec![6u8, 0u8],
        b"c".to_vec(),
        vec![7u8, 0u8],
    ];

    assert_eq!(hasher.args, expected);
}
