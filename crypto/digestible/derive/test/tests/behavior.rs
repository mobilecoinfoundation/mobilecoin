// Copyright (c) 2018-2021 The MobileCoin Foundation

/// Tests of the behavior of the macro-generated Digestible implementations
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_digestible_test_utils::*;

// Test structs
#[derive(Digestible)]
struct ExampleStruct {
    a: u16,
    b: u16,
    c: u16,
}

#[derive(Digestible)]
#[digestible(name = "ExampleStruct")]
struct ExampleStruct2 {
    c: u16,
    b: u16,
    a: u16,
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
    f: ExampleStruct,
}

// A Bar with a transparent field (but a different structure name)
#[derive(Digestible)]
struct BarWithTransparent {
    d: TransBlob,
    e: u32,
    f: ExampleStruct,
}

// A struct with a generic parameter and members
#[derive(Digestible)]
struct GenericExampleStruct<X: Digestible> {
    a: X,
    b: X,
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

// Test that ExampleStruct2 has fields in given order and not alphabetical order
#[test]
fn example_struct2() {
    let arg = ExampleStruct2 { a: 0, b: 1, c: 2 };
    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"foo1",
        name: b"ExampleStruct".to_vec(),
        elems: vec![
            ASTNode::from(ASTPrimitive {
                context: b"c",
                type_name: b"uint",
                data: vec![2u8, 0u8],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"b",
                type_name: b"uint",
                data: vec![1u8, 0u8],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"a",
                type_name: b"uint",
                data: vec![0u8, 0u8],
            }),
        ],
        is_completed: true,
    });
    digestible_test_case_ast("foo1", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"foo1"),
        [
            72, 44, 56, 17, 86, 202, 143, 191, 204, 74, 217, 227, 133, 204, 8, 16, 47, 75, 178,
            109, 202, 254, 222, 249, 89, 196, 247, 8, 140, 14, 167, 182
        ]
    );
}

// Test that ExampleStruct2 is not interchangeable with ExampleStruct
#[test]
fn example_struct_interchangeability() {
    let arg = ExampleStruct2 { a: 7, b: 5, c: 19 };
    let arg2 = ExampleStruct { a: 7, b: 5, c: 19 };
    assert_ne!(
        arg.digest32::<MerlinTranscript>(b"test"),
        arg2.digest32::<MerlinTranscript>(b"test")
    );
}

#[derive(Digestible)]
struct Tricky {
    field: Vec<i32>,
    fi_eld: Vec<i32>,
    _field: Vec<i32>,
    prim: bool,
    agg: String,
    seq: Vec<ExampleStruct>,
    var: Option<ExampleStruct2>,
}

// Test that a struct with tricky field names is being parsed and hashed as
// expected
#[test]
fn tricky_struct() {
    let arg = Tricky {
        field: vec![1],
        fi_eld: vec![2],
        _field: vec![3],
        prim: false,
        agg: "var".to_string(),
        seq: Default::default(),
        var: Some(ExampleStruct2 { a: 0, b: 1, c: 2 }),
    };
    let expected_var_ast = ASTNode::from(ASTAggregate {
        context: b"var",
        name: b"ExampleStruct".to_vec(),
        elems: vec![
            ASTNode::from(ASTPrimitive {
                context: b"c",
                type_name: b"uint",
                data: vec![2u8, 0u8],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"b",
                type_name: b"uint",
                data: vec![1u8, 0u8],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"a",
                type_name: b"uint",
                data: vec![0u8, 0u8],
            }),
        ],
        is_completed: true,
    });
    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"tricky",
        name: b"Tricky".to_vec(),
        elems: vec![
            ASTNode::from(ASTSequence {
                context: b"field",
                len: 1,
                elems: vec![ASTNode::from(ASTPrimitive {
                    context: b"",
                    type_name: b"int",
                    data: vec![1u8, 0u8, 0u8, 0u8],
                })],
            }),
            ASTNode::from(ASTSequence {
                context: b"fi_eld",
                len: 1,
                elems: vec![ASTNode::from(ASTPrimitive {
                    context: b"",
                    type_name: b"int",
                    data: vec![2u8, 0u8, 0u8, 0u8],
                })],
            }),
            ASTNode::from(ASTSequence {
                context: b"_field",
                len: 1,
                elems: vec![ASTNode::from(ASTPrimitive {
                    context: b"",
                    type_name: b"int",
                    data: vec![3u8, 0u8, 0u8, 0u8],
                })],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"prim",
                type_name: b"bool",
                data: vec![0u8],
            }),
            ASTNode::from(ASTPrimitive {
                context: b"agg",
                type_name: b"str",
                data: b"var".to_vec(),
            }),
            expected_var_ast,
        ],
        is_completed: true,
    });
    digestible_test_case_ast("tricky", &arg, expected_ast);
    assert_eq!(
        arg.digest32::<MerlinTranscript>(b"tricky"),
        [
            7, 77, 36, 165, 11, 239, 19, 38, 44, 127, 117, 48, 130, 150, 9, 58, 103, 36, 174, 126,
            78, 182, 101, 201, 194, 14, 47, 227, 220, 99, 6, 143
        ]
    );
}

// Test that an instance of Blob is being mapped to AST and hashed as expected
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

// Test that an instance of TransBlob is being mapped to AST and hashed as
// expected
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

// Test that an instance of Bar is being mapped to AST and hashed as expected
#[test]
fn bar1() {
    let arg = Bar {
        d: Blob(b"Koala".to_vec()),
        e: u32::max_value(),
        f: ExampleStruct { a: 5, b: 6, c: 7 },
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
                name: b"ExampleStruct".to_vec(),
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
            214, 103, 124, 244, 227, 71, 218, 40, 112, 211, 130, 16, 139, 166, 53, 222, 255, 143,
            99, 32, 21, 17, 93, 118, 15, 237, 67, 161, 33, 130, 76, 65
        ]
    );
}

// Test that an instance of BarWithTransparent is being mapped to AST and hashed
// as expected
#[test]
fn bar2() {
    let arg = BarWithTransparent {
        d: TransBlob(b"Koala".to_vec()),
        e: u32::max_value(),
        f: ExampleStruct { a: 5, b: 6, c: 7 },
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
                name: b"ExampleStruct".to_vec(),
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
            191, 9, 66, 251, 105, 132, 21, 123, 90, 28, 40, 211, 231, 168, 150, 16, 148, 48, 82,
            65, 4, 141, 187, 101, 72, 238, 241, 197, 85, 34, 142, 249
        ]
    );
}

// Test cases for GenericExampleStruct::<u32> and
// GenericExampleStruct::<Option<u32>>
#[test]
fn generic_example_struct1() {
    let arg = GenericExampleStruct {
        a: 123 as u32,
        b: 456 as u32,
    };

    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"genfoo1",
        name: b"GenericExampleStruct".to_vec(),
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
            77, 201, 127, 225, 56, 107, 48, 148, 235, 56, 108, 130, 31, 185, 54, 31, 82, 211, 48,
            94, 227, 85, 8, 161, 189, 241, 84, 171, 69, 0, 95, 109
        ]
    );

    let arg2 = GenericExampleStruct {
        a: Some(123 as u32),
        b: Some(456 as u32),
    };

    digestible_test_case_ast("genfoo1", &arg2, expected_ast);
    assert_eq!(
        arg2.digest32::<MerlinTranscript>(b"genfoo1"),
        [
            77, 201, 127, 225, 56, 107, 48, 148, 235, 56, 108, 130, 31, 185, 54, 31, 82, 211, 48,
            94, 227, 85, 8, 161, 189, 241, 84, 171, 69, 0, 95, 109
        ]
    );
}

// Test cases for GenericExampleStruct::<i32> and
// GenericExampleStruct::<Option<i32>>
#[test]
fn generic_example_struct2() {
    let arg = GenericExampleStruct {
        a: 123 as i32,
        b: 456 as i32,
    };

    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"genfoo2",
        name: b"GenericExampleStruct".to_vec(),
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
            27, 164, 2, 106, 152, 28, 209, 36, 245, 234, 252, 175, 99, 43, 159, 210, 187, 204, 78,
            238, 220, 43, 143, 239, 232, 89, 245, 87, 170, 14, 217, 198
        ]
    );

    let arg2 = GenericExampleStruct {
        a: Some(123 as i32),
        b: Some(456 as i32),
    };

    digestible_test_case_ast("genfoo2", &arg2, expected_ast);
    assert_eq!(
        arg2.digest32::<MerlinTranscript>(b"genfoo2"),
        [
            27, 164, 2, 106, 152, 28, 209, 36, 245, 234, 252, 175, 99, 43, 159, 210, 187, 204, 78,
            238, 220, 43, 143, 239, 232, 89, 245, 87, 170, 14, 217, 198
        ]
    );
}

// Test cases for GenericExampleStruct::<String> and
// GenericExampleStruct::<Option<String>>
#[test]
fn generic_example_struct3() {
    let arg = GenericExampleStruct {
        a: String::from("str1"),
        b: String::from("str2"),
    };

    let expected_ast = ASTNode::from(ASTAggregate {
        context: b"genfoo3",
        name: b"GenericExampleStruct".to_vec(),
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
            93, 6, 80, 35, 32, 166, 252, 185, 172, 99, 15, 69, 157, 45, 10, 1, 56, 227, 232, 229,
            16, 90, 97, 138, 80, 139, 46, 11, 243, 66, 11, 169
        ]
    );

    let arg2 = GenericExampleStruct {
        a: Some(String::from("str1")),
        b: Some(String::from("str2")),
    };

    digestible_test_case_ast("genfoo3", &arg2, expected_ast);
    assert_eq!(
        arg2.digest32::<MerlinTranscript>(b"genfoo3"),
        [
            93, 6, 80, 35, 32, 166, 252, 185, 172, 99, 15, 69, 157, 45, 10, 1, 56, 227, 232, 229,
            16, 90, 97, 138, 80, 139, 46, 11, 243, 66, 11, 169
        ]
    );
}
