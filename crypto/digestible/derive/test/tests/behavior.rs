// Copyright (c) 2018-2020 MobileCoin Inc.

/// Tests of the behavior of the macro-generated Digestible implementations
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_digestible_test_utils::*;

// Test structs
#[derive(Digestible)]
struct Foo {
    a: u16,
    b: u16,
    c: u16,
}

#[derive(Digestible)]
struct Blob(Vec<u8>);

// A structure equivalent to Blob that has been marked transparent
#[derive(Digestible)]
#[digestible(transparent)]
struct TransBlob(Vec<u8>);

#[derive(Digestible)]
struct Bar {
    d: Blob,
    e: u32,
    f: Foo,
}

// A Bar with a transparent field (but a different structure name)
#[derive(Digestible)]
struct BarWithTransparent {
    d: TransBlob,
    e: u32,
    f: Foo,
}

// A struct with a generic parameter and members
#[derive(Digestible)]
struct GenericFoo<X: Digestible> {
    a: X,
    b: X,
}

#[test]
fn foo1() {
    let arg = Foo { a: 0, b: 1, c: 2 };
    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"foo1",
        name: b"Foo".to_vec(),
        elems: vec![
            ASTNode::from(ASTPrimitive {
                context: b"a",
                type_name: b"uint",
                data: vec![0u8, 0u8],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"b",
                type_name: b"uint",
                data: vec![1u8, 0u8],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"c",
                type_name: b"uint",
                data: vec![2u8, 0u8],
            }),
        ],
        is_completed: true,
    });
    digestible_test_case_ast("foo1", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"foo1"),
        [
            44, 174, 200, 201, 207, 72, 151, 193, 63, 97, 49, 112, 135, 50, 252, 61, 211, 208, 41,
            4, 241, 249, 90, 114, 181, 197, 177, 151, 39, 165, 76, 197
        ]
    );
}

#[test]
fn blob1() {
    let arg = Blob(vec![1, 2, 3, 4]);
    let expected_ast = ASTNode::Aggregate(ASTAggregate {
        context: b"blob1",
        name: b"Blob".to_vec(),
        elems: vec![ASTNode::Primitive(ASTPrimitive {
            context: b"0",
            type_name: b"bytes",
            data: vec![1u8, 2u8, 3u8, 4u8],
        })],
        is_completed: true,
    });
    digestible_test_case_ast("blob1", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"blob1"),
        [
            59, 63, 205, 99, 4, 221, 221, 230, 90, 1, 135, 226, 106, 52, 210, 105, 88, 37, 182, 26,
            208, 240, 152, 4, 226, 0, 204, 11, 10, 187, 14, 48
        ]
    );
}

#[test]
fn blob2() {
    let arg = TransBlob(vec![1, 2, 3, 4]);
    let expected_ast = ASTNode::Primitive(ASTPrimitive {
        context: b"blob2",
        type_name: b"bytes",
        data: vec![1u8, 2u8, 3u8, 4u8],
    });
    digestible_test_case_ast("blob2", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"blob2"),
        [
            221, 88, 184, 210, 180, 30, 40, 40, 89, 37, 221, 90, 185, 33, 199, 133, 99, 102, 67,
            196, 197, 85, 67, 234, 151, 160, 111, 230, 234, 125, 181, 1
        ]
    );
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"blob2"),
        vec![1u8, 2u8, 3u8, 4u8].digest32::<MerlinTranscript>(b"blob2")
    );
}

#[test]
fn bar1() {
    let arg = Bar {
        d: Blob(b"Koala".to_vec()),
        e: u32::max_value(),
        f: Foo { a: 5, b: 6, c: 7 },
    };
    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"bar1",
        name: b"Bar".to_vec(),
        elems: vec![
            ASTNode::from(ASTAggregate {
                context: b"d",
                name: b"Blob".to_vec(),
                elems: vec![ASTNode::from(ASTPrimitive {
                    context: b"0",
                    type_name: b"bytes",
                    data: b"Koala".to_vec(),
                })],
                is_completed: true,
            }),
            ASTNode::from(ASTPrimitive {
                context: b"e",
                type_name: b"uint",
                data: vec![255u8; 4],
            }),
            ASTNode::from(ASTAggregate {
                context: b"f",
                name: b"Foo".to_vec(),
                elems: vec![
                    ASTNode::from(ASTPrimitive {
                        context: b"a",
                        type_name: b"uint",
                        data: vec![5u8, 0u8],
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"b",
                        type_name: b"uint",
                        data: vec![6u8, 0u8],
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"c",
                        type_name: b"uint",
                        data: vec![7u8, 0u8],
                    }),
                ],
                is_completed: true,
            }),
        ],
        is_completed: true,
    });
    digestible_test_case_ast("bar1", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"bar1"),
        [
            237, 231, 204, 138, 55, 249, 219, 0, 154, 213, 236, 77, 123, 104, 185, 68, 165, 117,
            179, 15, 85, 65, 13, 134, 163, 16, 206, 60, 249, 184, 194, 81
        ]
    );
}

#[test]
fn bar2() {
    let arg = BarWithTransparent {
        d: TransBlob(b"Koala".to_vec()),
        e: u32::max_value(),
        f: Foo { a: 5, b: 6, c: 7 },
    };
    let expected_ast = ASTNode::Aggregate(ASTAggregate {
        context: b"bar2",
        name: b"BarWithTransparent".to_vec(),
        elems: vec![
            ASTNode::from(ASTPrimitive {
                context: b"d",
                type_name: b"bytes",
                data: b"Koala".to_vec(),
            }),
            ASTNode::from(ASTPrimitive {
                context: b"e",
                type_name: b"uint",
                data: vec![255u8; 4],
            }),
            ASTNode::from(ASTAggregate {
                context: b"f",
                name: b"Foo".to_vec(),
                elems: vec![
                    ASTNode::from(ASTPrimitive {
                        context: b"a",
                        type_name: b"uint",
                        data: vec![5u8, 0u8],
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"b",
                        type_name: b"uint",
                        data: vec![6u8, 0u8],
                    }),
                    ASTNode::from(ASTPrimitive {
                        context: b"c",
                        type_name: b"uint",
                        data: vec![7u8, 0u8],
                    }),
                ],
                is_completed: true,
            }),
        ],
        is_completed: true,
    });
    digestible_test_case_ast("bar2", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"bar2"),
        [
            227, 207, 254, 59, 174, 133, 174, 192, 215, 106, 9, 247, 177, 243, 206, 25, 185, 103,
            123, 66, 81, 133, 60, 234, 71, 175, 225, 143, 247, 195, 65, 250
        ]
    );
}

// Test cases for GenericFoo::<u32> and GenericFoo::<Option<u32>>
#[test]
fn generic_foo1() {
    let arg = GenericFoo {
        a: 123 as u32,
        b: 456 as u32,
    };

    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"genfoo1",
        name: b"GenericFoo".to_vec(),
        elems: vec![
            ASTNode::from(ASTPrimitive {
                context: b"a",
                type_name: b"uint",
                data: 123u32.to_le_bytes().to_vec(),
            }),
            ASTNode::from(ASTPrimitive {
                context: b"b",
                type_name: b"uint",
                data: 456u32.to_le_bytes().to_vec(),
            }),
        ],
        is_completed: true,
    });
    digestible_test_case_ast("genfoo1", &arg, expected_ast.clone());
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"genfoo1"),
        [
            194, 207, 55, 95, 52, 136, 167, 235, 136, 171, 231, 204, 239, 42, 41, 163, 56, 87, 130,
            74, 1, 23, 20, 98, 33, 36, 3, 82, 31, 91, 104, 94
        ]
    );

    let arg2 = GenericFoo {
        a: Some(123 as u32),
        b: Some(456 as u32),
    };

    digestible_test_case_ast("genfoo1", &arg2, expected_ast);
    assert_eq!(
        arg2.digest32::<MerlinTranscript>(b"genfoo1"),
        [
            194, 207, 55, 95, 52, 136, 167, 235, 136, 171, 231, 204, 239, 42, 41, 163, 56, 87, 130,
            74, 1, 23, 20, 98, 33, 36, 3, 82, 31, 91, 104, 94
        ]
    );
}

// Test cases for GenericFoo::<i32> and GenericFoo::<Option<i32>>
#[test]
fn generic_foo2() {
    let arg = GenericFoo {
        a: 123 as i32,
        b: 456 as i32,
    };

    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"genfoo2",
        name: b"GenericFoo".to_vec(),
        elems: vec![
            ASTNode::from(ASTPrimitive {
                context: b"a",
                type_name: b"int",
                data: 123u32.to_le_bytes().to_vec(),
            }),
            ASTNode::from(ASTPrimitive {
                context: b"b",
                type_name: b"int",
                data: 456u32.to_le_bytes().to_vec(),
            }),
        ],
        is_completed: true,
    });
    digestible_test_case_ast("genfoo2", &arg, expected_ast.clone());
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"genfoo2"),
        [
            90, 161, 44, 125, 167, 199, 138, 29, 78, 51, 65, 96, 90, 232, 178, 183, 105, 117, 194,
            127, 194, 17, 213, 218, 168, 146, 198, 211, 216, 161, 133, 86
        ]
    );

    let arg2 = GenericFoo {
        a: Some(123 as i32),
        b: Some(456 as i32),
    };

    digestible_test_case_ast("genfoo2", &arg2, expected_ast);
    assert_eq!(
        arg2.digest32::<MerlinTranscript>(b"genfoo2"),
        [
            90, 161, 44, 125, 167, 199, 138, 29, 78, 51, 65, 96, 90, 232, 178, 183, 105, 117, 194,
            127, 194, 17, 213, 218, 168, 146, 198, 211, 216, 161, 133, 86
        ]
    );
}

// Test cases for GenericFoo::<String> and GenericFoo::<Option<String>>
#[test]
fn generic_foo3() {
    let arg = GenericFoo {
        a: String::from("str1"),
        b: String::from("str2"),
    };

    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"genfoo3",
        name: b"GenericFoo".to_vec(),
        elems: vec![
            ASTNode::from(ASTPrimitive {
                context: b"a",
                type_name: b"str",
                data: "str1".as_bytes().to_vec(),
            }),
            ASTNode::from(ASTPrimitive {
                context: b"b",
                type_name: b"str",
                data: "str2".as_bytes().to_vec(),
            }),
        ],
        is_completed: true,
    });
    digestible_test_case_ast("genfoo3", &arg, expected_ast.clone());
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"genfoo3"),
        [
            28, 20, 69, 136, 101, 151, 13, 213, 236, 10, 150, 120, 14, 40, 33, 216, 35, 60, 209,
            16, 98, 94, 21, 175, 244, 13, 7, 79, 58, 50, 116, 6
        ]
    );

    let arg2 = GenericFoo {
        a: Some(String::from("str1")),
        b: Some(String::from("str2")),
    };

    digestible_test_case_ast("genfoo3", &arg2, expected_ast);
    assert_eq!(
        arg2.digest32::<MerlinTranscript>(b"genfoo3"),
        [
            28, 20, 69, 136, 101, 151, 13, 213, 236, 10, 150, 120, 14, 40, 33, 216, 35, 60, 209,
            16, 98, 94, 21, 175, 244, 13, 7, 79, 58, 50, 116, 6
        ]
    );
}
