// Copyright (c) 2018-2022 The MobileCoin Foundation

/// Tests of the behavior of the macro-generated Digestible implementations
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_digestible_test_utils::*;

// Test struct
#[derive(Digestible)]
struct ExampleStruct {
    a: u16,
    b: u16,
    c: u16,
}

// Test enum
#[derive(Digestible)]
enum ExampleEnum {
    A(u16),
    B(ExampleStruct),
    C(bool),
}

#[derive(Digestible)]
#[digestible(name = "ExampleStruct")]
struct ExampleStruct2 {
    a: u16,
    b: u16,
    c: ExampleEnum,
}

// Enum with transparent
#[derive(Digestible)]
#[digestible(transparent)]
enum TransEnum {
    A(u16),
    B(ExampleStruct),
    C(bool),
}

#[derive(Digestible)]
#[digestible(name = "ExampleStruct")]
struct ExampleStruct3 {
    a: u16,
    b: u16,
    c: TransEnum,
}

// Test that an A instance of ExampleEnum is being mapped to AST and hashed as
// expected
#[test]
fn example_enum_a() {
    let arg = ExampleEnum::A(3);
    let expected_ast = ASTNode::from(ASTVariant {
        context: b"A_test",
        name: b"ExampleEnum".to_vec(),
        which: 0,
        value: Some(Box::new(ASTNode::from(ASTPrimitive {
            context: b"A",
            type_name: b"uint",
            data: vec![3u8, 0u8],
        }))),
    });
    digestible_test_case_ast("A_test", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"A_test"),
        [
            220, 18, 138, 81, 150, 254, 86, 19, 251, 114, 183, 26, 36, 163, 149, 226, 100, 158, 68,
            213, 190, 219, 82, 220, 228, 148, 139, 190, 110, 244, 238, 220
        ]
    );
}

// Test that a B instance of ExampleEnum is being mapped to AST and hashed as
// expected
#[test]
fn example_enum_b() {
    let arg = ExampleEnum::B(ExampleStruct { a: 0, b: 1, c: 2 });
    let expected_ast = ASTNode::from(ASTVariant {
        context: b"B_test",
        name: b"ExampleEnum".to_vec(),
        which: 1,
        value: Some(Box::new(ASTNode::from(ASTAggregate {
            context: b"B",
            name: b"ExampleStruct".to_vec(),
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
        }))),
    });
    digestible_test_case_ast("B_test", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"B_test"),
        [
            50, 246, 247, 147, 99, 239, 185, 52, 199, 224, 32, 139, 105, 56, 188, 103, 146, 175,
            74, 71, 151, 42, 18, 123, 38, 163, 180, 85, 22, 128, 126, 177
        ]
    );
}

// Test that a C instance of ExampleEnum is being mapped to AST and hashed as
// expected
#[test]
fn example_enum_c() {
    let arg = ExampleEnum::C(true);
    let expected_ast = ASTNode::from(ASTVariant {
        context: b"C_test",
        name: b"ExampleEnum".to_vec(),
        which: 2,
        value: Some(Box::new(ASTNode::from(ASTPrimitive {
            context: b"C",
            type_name: b"bool",
            data: vec![1u8],
        }))),
    });
    digestible_test_case_ast("C_test", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"C_test"),
        [
            220, 136, 150, 83, 136, 170, 75, 139, 190, 220, 183, 47, 84, 174, 53, 244, 190, 64, 75,
            154, 254, 21, 252, 153, 118, 31, 139, 221, 171, 170, 207, 121
        ]
    );
}

// Test that an A instance of TransEnum is being mapped to AST and hashed as
// expected
#[test]
fn trans_enum_a() {
    let arg = TransEnum::A(3);
    let expected_ast = ASTNode::from(ASTPrimitive {
        context: b"A_test",
        type_name: b"uint",
        data: vec![3u8, 0u8],
    });
    digestible_test_case_ast("A_test", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"A_test"),
        3u16.digest32::<MerlinTranscript>(b"A_test")
    );
}

// Test that a B instance of ExampleEnum is being mapped to AST and hashed as
// expected
#[test]
fn trans_enum_b() {
    let arg = TransEnum::B(ExampleStruct { a: 0, b: 1, c: 2 });
    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"B_test",
        name: b"ExampleStruct".to_vec(),
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
    digestible_test_case_ast("B_test", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"B_test"),
        ExampleStruct { a: 0, b: 1, c: 2 }.digest32::<MerlinTranscript>(b"B_test")
    );
}

// Test that a C instance of ExampleEnum is being mapped to AST and hashed as
// expected
#[test]
fn trans_enum_c() {
    let arg = TransEnum::C(false);
    let expected_ast = ASTNode::from(ASTPrimitive {
        context: b"C_test",
        type_name: b"bool",
        data: vec![0u8],
    });
    digestible_test_case_ast("C_test", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"C_test"),
        false.digest32::<MerlinTranscript>(b"C_test")
    );
}

// Test that ExampleStruct is interchangeable with TransEnum(ExampleStruct)
#[test]
fn trans_enum_struct_interchangeability() {
    let arg = ExampleStruct { a: 7, b: 5, c: 19 };
    let arg2 = TransEnum::B(ExampleStruct { a: 7, b: 5, c: 19 });
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"test"),
        arg2.digest32::<MerlinTranscript>(b"test")
    );
}

// Test that ExampleStruct2 is not interchangeable with ExampleStruct
#[test]
fn example_struct_interchangeability() {
    let arg = ExampleStruct { a: 7, b: 5, c: 19 };
    let arg2 = ExampleStruct2 {
        a: 7,
        b: 5,
        c: ExampleEnum::A(19),
    };
    assert_ne!(
        arg.digest32::<MerlinTranscript>(b"test"),
        arg2.digest32::<MerlinTranscript>(b"test")
    );
}

// Test that ExampleStruct3 is interchangeable with ExampleStruct
#[test]
fn example_struct_interchangeability3() {
    let arg = ExampleStruct { a: 7, b: 5, c: 19 };
    let arg2 = ExampleStruct3 {
        a: 7,
        b: 5,
        c: TransEnum::A(19),
    };
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"test"),
        arg2.digest32::<MerlinTranscript>(b"test")
    );
}

// Test that an instance of ExampleStruct is being mapped to AST and hashed as
// expected
#[test]
fn example_struct1() {
    let arg = ExampleStruct { a: 0, b: 1, c: 2 };
    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"foo1",
        name: b"ExampleStruct".to_vec(),
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
            19, 53, 9, 198, 156, 34, 144, 43, 162, 78, 50, 32, 131, 61, 167, 17, 13, 139, 228, 70,
            4, 145, 120, 36, 160, 118, 131, 86, 224, 154, 10, 110
        ]
    );
}

// Test that ExampleStruct2 is being mapped to an AST as expected
#[test]
fn example_struct2() {
    let arg = ExampleStruct2 {
        a: 0,
        b: 1,
        c: ExampleEnum::C(true),
    };
    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"foo1",
        name: b"ExampleStruct".to_vec(),
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
            ASTNode::from(ASTVariant {
                context: b"c",
                name: b"ExampleEnum".to_vec(),
                which: 2,
                value: Some(Box::new(ASTNode::from(ASTPrimitive {
                    context: b"C",
                    type_name: b"bool",
                    data: vec![1u8],
                }))),
            }),
        ],
        is_completed: true,
    });
    digestible_test_case_ast("foo1", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"foo1"),
        [
            159, 244, 234, 57, 119, 244, 123, 152, 147, 44, 113, 52, 181, 117, 162, 233, 66, 73,
            46, 210, 255, 18, 110, 140, 19, 20, 15, 173, 128, 189, 213, 47
        ]
    );
}

// Test that ExampleStruct3 is being mapped to an AST as expected.
#[test]
fn example_struct3() {
    let arg = ExampleStruct3 {
        a: 0,
        b: 1,
        c: TransEnum::C(true),
    };
    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"foo1",
        name: b"ExampleStruct".to_vec(),
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
                type_name: b"bool",
                data: vec![1u8],
            }),
        ],
        is_completed: true,
    });
    digestible_test_case_ast("foo1", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"foo1"),
        [
            41, 79, 252, 70, 13, 80, 217, 161, 226, 27, 73, 38, 252, 37, 224, 82, 62, 191, 54, 42,
            14, 26, 249, 174, 4, 186, 29, 196, 44, 88, 71, 228
        ]
    );
}
