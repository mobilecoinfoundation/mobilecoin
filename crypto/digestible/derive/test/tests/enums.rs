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
    C,
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
    C,
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
        value: Some(Box::new(
            ASTNode::from(ASTPrimitive {
                context: b"A",
                type_name: b"uint",
                data: vec![3u8, 0u8],
            }),
        )),
    });
    digestible_test_case_ast("A_test", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"A_test"),
        [220, 18, 138, 81, 150, 254, 86, 19, 251, 114, 183, 26, 36, 163, 149, 226, 100, 158, 68, 213, 190, 219, 82, 220, 228, 148, 139, 190, 110, 244, 238, 220]
    );
}

// Test that a B instance of ExampleEnum is being mapped to AST and hashed as
// expected
#[test]
fn example_enum_b() {
    let arg = ExampleEnum::B(ExampleStruct { a: 0, b: 1, c: 2});
    let expected_ast = ASTNode::from(ASTVariant {
        context: b"B_test",
        name: b"ExampleEnum".to_vec(),
        which: 1,
        value: Some(Box::new(
            ASTNode::from(ASTAggregate {
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
                })
        )),
    });
    digestible_test_case_ast("B_test", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"B_test"),
        [50, 246, 247, 147, 99, 239, 185, 52, 199, 224, 32, 139, 105, 56, 188, 103, 146, 175, 74, 71, 151, 42, 18, 123, 38, 163, 180, 85, 22, 128, 126, 177]
    );
}

// Test that a C instance of ExampleEnum is being mapped to AST and hashed as
// expected
#[test]
fn example_enum_c() {
    let arg = ExampleEnum::C;
    let expected_ast = ASTNode::from(ASTVariant {
        context: b"C_test",
        name: b"ExampleEnum".to_vec(),
        which: 2,
        value: Some(Box::new(
            ASTNode::from(ASTNone{ context: b"C"})
        )),
    });
    digestible_test_case_ast("C_test", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"C_test"),
        [36, 116, 29, 101, 185, 20, 3, 39, 50, 65, 57, 25, 15, 236, 167, 119, 53, 69, 6, 19, 134, 181, 97, 14, 175, 109, 81, 67, 31, 245, 205, 237]
    );
}

// Test that an A instance of TransEnum is being mapped to AST and hashed as
// expected
#[test]
fn trans_enum_a() {
    let arg = TransEnum::A(3);
    let expected_ast =
            ASTNode::from(ASTPrimitive {
                context: b"A_test",
                type_name: b"uint",
                data: vec![3u8, 0u8],
            });
    digestible_test_case_ast("A_test", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"A_test"),
        [196, 66, 116, 1, 87, 75, 116, 241, 250, 78, 20, 22, 208, 227, 89, 118, 121, 77, 109, 255, 15, 184, 217, 249, 111, 181, 66, 141, 37, 23, 204, 243]
    );
}

// Test that a B instance of ExampleEnum is being mapped to AST and hashed as
// expected
#[test]
fn trans_enum_b() {
    let arg = TransEnum::B(ExampleStruct { a: 0, b: 1, c: 2});
    let expected_ast =
            ASTNode::from(ASTAggregate {
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
        [101, 107, 59, 55, 249, 37, 221, 203, 13, 36, 193, 85, 104, 62, 192, 193, 243, 144, 224, 171, 85, 200, 48, 29, 36, 71, 187, 89, 102, 228, 109, 87]
    );
}

// Test that a C instance of ExampleEnum is being mapped to AST and hashed as
// expected
#[test]
fn trans_enum_c() {
    let arg = TransEnum::C;
    let expected_ast = ASTNode::from(ASTNone{ context: b"C_test"} );
    digestible_test_case_ast("C_test", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"C_test"),
        [252, 90, 24, 108, 60, 163, 129, 134, 13, 8, 161, 22, 224, 185, 29, 10, 36, 94, 118, 145, 198, 122, 124, 191, 202, 246, 157, 170, 115, 124, 84, 154]
    );
}

// Test that ExampleStruct is interchangeable with TransEnum(ExampleStruct)
// Test that ExampleStruct2 is not interchangeable with ExampleStruct
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
    let arg2 = ExampleStruct2 { a: 7, b: 5, c: ExampleEnum::A(19) };
    assert_ne!(
        arg.digest32::<MerlinTranscript>(b"test"),
        arg2.digest32::<MerlinTranscript>(b"test")
    );
}

// Test that ExampleStruct3 is interchangeable with ExampleStruct
#[test]
fn example_struct_interchangeability3() {
    let arg = ExampleStruct { a: 7, b: 5, c: 19 };
    let arg2 = ExampleStruct3 { a: 7, b: 5, c: TransEnum::A(19) };
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
    let arg = ExampleStruct2 { a: 0, b: 1, c: ExampleEnum::C };
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
                value: Some(Box::new(
                    ASTNode::from(ASTNone{context: b"C"})
                )),
            }),
        ],
        is_completed: true,
    });
    digestible_test_case_ast("foo1", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"foo1"),
        [158, 86, 252, 228, 26, 251, 185, 40, 27, 106, 31, 99, 211, 11, 9, 81, 137, 138, 230, 218, 134, 127, 148, 109, 129, 200, 13, 34, 191, 15, 53, 93]
    );
}

// Test that ExampleStruct3 is being mapped to an AST as expected,
// with the vacant TransEnum being skipped, because "empty" struct members
// are allowed to be omitted when hashing.
#[test]
fn example_struct3() {
    let arg = ExampleStruct3 { a: 0, b: 1, c: TransEnum::C };
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
        ],
        is_completed: true,
    });
    digestible_test_case_ast("foo1", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"foo1"),
        [181, 165, 79, 230, 141, 89, 228, 0, 79, 208, 172, 197, 83, 24, 220, 112, 136, 232, 68, 201, 142, 6, 49, 26, 255, 126, 146, 204, 143, 36, 94, 67]
    );
}
